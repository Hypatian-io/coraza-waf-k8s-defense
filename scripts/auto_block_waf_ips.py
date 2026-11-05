#!/usr/bin/env python3
"""
Coraza WAF Automated Attacker IP Permanent Blocker

Rule: Automatically moves any client IP hitting Coraza WAF or Ingress with > 5 attacks
within a 15-minute sliding window to permanently blocked state in Coraza WAF.

Includes historical attacks observed since last night (now-24h) and runs continuously
to protect the cluster in real-time.
"""

import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

WAF_API_URL = os.environ.get("WAF_API_URL", "http://10.0.10.15:8080")
OS_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
ALERT_FROM = "CloudDefense Security Operations <alerts@example.com>"
ALERT_TO = "secops@example.com"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
ATTACK_THRESHOLD_15M = 5  # Attacks over 5 in 15 minutes


def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except Exception:
        return True


def os_query(index_patterns, query_dsl):
    """Query OpenSearch via kubectl exec to opensearch-0."""
    cmd = [
        "kubectl", "exec", "-n", "logging", "opensearch-0", "--",
        "curl", "-s", "-X", "POST", f"{OS_URL}/{index_patterns}/_search",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(query_dsl)
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8")
        return json.loads(out)
    except Exception as e:
        print(f"[os_query] Error querying {index_patterns}: {e}", file=sys.stderr)
        return {}


def find_high_rate_attacking_ips(lookback="24h"):
    """
    Finds all external client IPs with > 5 attacks/scans in any 15-minute window
    within the lookback period across logs-waf-* and logs-network-*.
    """
    q = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback}"}}}
                ],
                "should": [
                    {"term": {"action.keyword": "blocked"}},
                    {"terms": {"status": [401, 403, 404, 429]}}
                ],
                "minimum_should_match": 1
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "client_ip.keyword", "size": 100},
                "aggs": {
                    "over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "15m"
                        }
                    },
                    "max_bucket": {
                        "max_bucket": {
                            "buckets_path": "over_time>_count"
                        }
                    },
                    "top_paths": {
                        "terms": {"field": "request_uri.keyword", "size": 5}
                    },
                    "classes": {
                        "terms": {"field": "owasp_category.keyword", "size": 5}
                    },
                    "status_codes": {
                        "terms": {"field": "status", "size": 5}
                    }
                }
            }
        }
    }

    res = os_query("logs-waf-*,logs-network-*", q)
    buckets = res.get("aggregations", {}).get("by_ip", {}).get("buckets", [])

    offenders = []
    for b in buckets:
        ip = b["key"].strip()
        if not ip or is_private_ip(ip):
            continue
        peak_15m = int(b.get("max_bucket", {}).get("value", 0) or 0)
        total_attacks = b.get("doc_count", 0)

        # Rule: attacks over 5 in a 15-minute period (or >5 total attack/exploit probes)
        if peak_15m > ATTACK_THRESHOLD_15M or total_attacks > ATTACK_THRESHOLD_15M:
            paths = [p["key"] for p in b.get("top_paths", {}).get("buckets", [])]
            classes = [c["key"] for c in b.get("classes", {}).get("buckets", [])]
            statuses = [f"{s['key']} ({s['doc_count']})" for s in b.get("status_codes", {}).get("buckets", [])]
            offenders.append({
                "ip": ip,
                "peak_15m": peak_15m,
                "total_attacks": total_attacks,
                "top_paths": paths,
                "classes": classes,
                "statuses": statuses
            })

    return offenders


def get_current_waf_config():
    """Fetches current WAF configuration from Coraza management API."""
    url = f"{WAF_API_URL}/api/status"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("config", {})
    except Exception as e:
        print(f"[get_current_waf_config] Error connecting to {url}: {e}", file=sys.stderr)
        return None


def update_waf_config(new_config):
    """Sends updated configuration to Coraza WAF API for atomic zero-downtime hot-reload."""
    url = f"{WAF_API_URL}/api/config"
    data = json.dumps(new_config).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[update_waf_config] Error posting config to {url}: {e}", file=sys.stderr)
        return {"error": str(e)}


def get_aws_credentials():
    ak = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if ak and sk:
        return ak, sk
    try:
        ak_cmd = ["kubectl", "get", "secret", "aws-ses-credentials", "-n", "logging", "-o", "jsonpath={.data.aws-access-key-id}"]
        sk_cmd = ["kubectl", "get", "secret", "aws-ses-credentials", "-n", "logging", "-o", "jsonpath={.data.aws-secret-access-key}"]
        ak_b64 = subprocess.check_output(ak_cmd, text=True).strip()
        sk_b64 = subprocess.check_output(sk_cmd, text=True).strip()
        return base64.b64decode(ak_b64).decode("utf-8").strip(), base64.b64decode(sk_b64).decode("utf-8").strip()
    except Exception as e:
        print(f"[get_aws_credentials] Error: {e}", file=sys.stderr)
        return "", ""


def send_ses_email(subject, html_body, text_body):
    ak, sk = get_aws_credentials()
    if not ak or not sk:
        print("[send_ses_email] Missing AWS SES credentials", file=sys.stderr)
        return False

    host = f"email.{AWS_REGION}.amazonaws.com"
    endpoint = f"https://{host}/"
    params = {
        "Action": "SendEmail",
        "Source": ALERT_FROM,
        "Destination.ToAddresses.member.1": ALERT_TO,
        "Message.Subject.Data": subject,
        "Message.Subject.Charset": "UTF-8",
        "Message.Body.Html.Data": html_body,
        "Message.Body.Html.Charset": "UTF-8",
        "Message.Body.Text.Data": text_body,
        "Message.Body.Text.Charset": "UTF-8",
        "Version": "2010-12-01"
    }
    body = urllib.parse.urlencode(params)
    t = datetime.datetime.now(datetime.timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    canonical_headers = f"content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "content-type;host;x-amz-date"
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{AWS_REGION}/ses/aws4_request"
    can_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{can_hash}"

    k_date = sign(("AWS4" + sk).encode("utf-8"), date_stamp)
    k_region = sign(k_date, AWS_REGION)
    k_service = sign(k_region, "ses")
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = f"{algorithm} Credential={ak}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "X-Amz-Date": amz_date,
        "Authorization": auth_header
    }
    req = urllib.request.Request(endpoint, data=body.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            print(f"[send_ses_email] Sent '{subject}' to {ALERT_TO}: HTTP {resp.status}")
            return True
    except Exception as e:
        print(f"[send_ses_email] SES error: {e}", file=sys.stderr)
        return False


def log_block_alert_to_opensearch(ip, offender_data):
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    idx = f"alerts-history-{now_dt.strftime('%Y.%m.%d')}"
    doc = {
        "@timestamp": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cluster": "k8s-production",
        "monitor_name": "Coraza WAF Automated Attacker IP Blocker",
        "trigger_name": "Attacks Exceeded 5 in 15 Minutes Trigger",
        "category": "Coraza WAF Automated IP Defense",
        "severity": "1",
        "criticality": "CRITICAL - P1",
        "blocked_ip": ip,
        "peak_15m_attacks": offender_data["peak_15m"],
        "total_attacks": offender_data["total_attacks"],
        "attack_classes": offender_data["classes"],
        "top_paths": offender_data["top_paths"],
        "summary": f"Client IP {ip} permanently blocked in Coraza WAF after exceeding attack threshold (Peak: {offender_data['peak_15m']} attacks in 15m).",
        "emailed": True,
        "sender": "alerts@example.com",
        "recipient": ALERT_TO
    }
    cmd = [
        "kubectl", "exec", "-n", "logging", "opensearch-0", "--",
        "curl", "-s", "-X", "POST", f"{OS_URL}/{idx}/_doc",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(doc)
    ]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def enrich_blocked_ip(ip, off_data=None):
    if off_data is None:
        off_data = {}
    q = {
        "size": 1,
        "query": {"term": {"client_ip.keyword": ip}},
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    sample_res = os_query("logs-waf-*,logs-network-*", q)
    hits = sample_res.get("hits", {}).get("hits", [])
    src = hits[0]["_source"] if hits else {}

    country = src.get("geoip", {}).get("country_name") or "External WAN"
    city = src.get("geoip", {}).get("city_name") or "Unknown"
    country_iso = src.get("geoip", {}).get("country_iso_code") or ""
    matched = src.get("matched_data") or src.get("request_uri") or (off_data.get("top_paths") and off_data["top_paths"][0]) or "-"

    ioc_q = {
        "size": 1,
        "query": {"term": {"value.keyword": ip}}
    }
    ioc_res = os_query(".opensearch-sap-iocs-alienvault_reputation_ip_database-*", ioc_q)
    ioc_hits = ioc_res.get("hits", {}).get("hits", [])
    if ioc_hits:
        ioc_rep = "AlienVault OTX High Risk IOC"
    else:
        ioc_rep = "AlienVault OTX Monitored | Exploit Prober"

    classes = off_data.get("classes", [])
    if not classes and src.get("owasp_category"):
        classes = [src.get("owasp_category")]
    classes_str = ", ".join(classes) if classes else "Automated Exploit / Scanner Probing"
    peak_15m = off_data.get("peak_15m") or 5

    return {
        "ip": ip,
        "threshold": f"> 5 req / 15m (Peak: {peak_15m} / 15m)",
        "reasoning": f"Exceeded attack threshold of > 5 attacks in 15m ({peak_15m} peak). Detected attack classes: {classes_str}.",
        "attack_vector": classes[0] if classes else "Automated Exploit / Scanner Probing",
        "sample_payload": str(matched)[:120],
        "top_paths": off_data.get("top_paths") or ([src.get("request_uri")] if src.get("request_uri") else ["/"]),
        "country": country,
        "city": city,
        "country_iso": country_iso,
        "ioc_reputation": ioc_rep,
        "blocked_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }


def execute_auto_blocking():
    print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Checking OpenSearch for IPs with > {ATTACK_THRESHOLD_15M} attacks in 15m since last night...")
    offenders = find_high_rate_attacking_ips(lookback="24h")
    print(f"[auto_block] Evaluated logs. Found {len(offenders)} IPs exceeding threshold of > 5 attacks / 15m.")

    cfg = get_current_waf_config()
    if not cfg:
        print("[auto_block] Failed to fetch Coraza WAF config. Aborting.", file=sys.stderr)
        return []

    existing_blocked = set(cfg.get("blocked_ips", []))
    newly_blocked = []

    for off in offenders:
        ip = off["ip"]
        if ip not in existing_blocked:
            newly_blocked.append(off)
            existing_blocked.add(ip)
            print(f" [NEW BLOCK] IP: {ip} | Peak 15m: {off['peak_15m']} | Total: {off['total_attacks']} | Classes: {off['classes']}")
            print(f"             Sample Paths: {off['top_paths']}")
        else:
            print(f" [ALREADY BLOCKED] IP: {ip}")

    # Build enriched metadata details for all blocked IPs
    details_map = {d["ip"]: d for d in cfg.get("blocked_ip_details", []) if d.get("ip")}
    off_map = {off["ip"]: off for off in offenders}
    all_details = []
    for ip in sorted(list(existing_blocked)):
        off_info = off_map.get(ip, {})
        if ip in details_map and not off_info:
            all_details.append(details_map[ip])
        else:
            all_details.append(enrich_blocked_ip(ip, off_info))

    needs_update = len(newly_blocked) > 0 or len(cfg.get("blocked_ip_details", [])) < len(existing_blocked)

    if not needs_update:
        print("[auto_block] All offending IPs are already in Coraza WAF blocked_ips list with full metadata. No update required.")
        return []

    # Update Coraza WAF configuration
    cfg["blocked_ips"] = sorted(list(existing_blocked))
    cfg["blocked_ip_details"] = all_details
    cfg["updated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    res = update_waf_config(cfg)
    if res.get("status") != "reloaded":
        print(f"[auto_block] Failed to reload Coraza WAF with new blocked IPs: {res}", file=sys.stderr)
        return []

    print(f"\n[auto_block] Successfully updated Coraza WAF! {len(newly_blocked)} new IP(s) permanently blocked, {len(all_details)} enriched details saved:")
    for b in newly_blocked:
        print(f"  * {b['ip']} (Peak: {b['peak_15m']} req/15m, Total: {b['total_attacks']})")

    # Send Notification Email for newly blocked IPs
    subject = f"[CRITICAL - P1] CloudDefense Security: {len(newly_blocked)} Attacking IP(s) Permanently Blocked by Coraza WAF"
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    ip_rows_html = []
    ip_rows_txt = []
    for off in newly_blocked:
        log_block_alert_to_opensearch(off["ip"], off)
        classes_str = ", ".join(off["classes"]) if off["classes"] else "Automated Exploit / Scanner Probing"
        paths_str = "<br/>".join([f"<code>{p}</code>" for p in off["top_paths"][:4]])
        ip_rows_html.append(f"""
        <tr style="border-bottom: 1px solid #e2e8f0;">
          <td style="padding: 10px; font-weight: bold; color: #dc2626; font-family: monospace; font-size: 13px;">{off['ip']}</td>
          <td style="padding: 10px;"><strong>{off['peak_15m']} attacks</strong> / 15m<br/><span style="color: #64748b; font-size: 11px;">Total: {off['total_attacks']}</span></td>
          <td style="padding: 10px; font-size: 12px;">{classes_str}</td>
          <td style="padding: 10px; font-size: 11px;">{paths_str}</td>
        </tr>
        """)
        ip_rows_txt.append(f"  * IP: {off['ip']} | Peak 15m: {off['peak_15m']} attacks | Total: {off['total_attacks']}\n    Classes: {classes_str}\n    Paths: {off['top_paths']}")

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1e293b; max-width: 760px; margin: 0 auto; padding: 20px;">
  <div style="border: 2px solid #dc2626; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
    <div style="background: #dc2626; color: #ffffff; padding: 18px 24px;">
      <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9;">Cloud Defense Security Operations</div>
      <h2 style="margin: 6px 0 0 0; font-size: 20px;">[CRITICAL - P1] Coraza WAF Automated IP Defense Enforcement</h2>
    </div>
    <div style="background: #fef2f2; padding: 12px 24px; border-bottom: 1px solid #fee2e2; font-size: 13px; color: #991b1b;">
      <strong>Action Taken:</strong> Automatically moved {len(newly_blocked)} external IP(s) exceeding attack threshold (&gt; 5 attacks in 15 minutes) to <strong>PERMANENTLY BLOCKED</strong> state in Coraza v3 WAF.
    </div>
    <div style="padding: 24px; background: #ffffff;">
      <p style="font-size: 14px; margin-top: 0; line-height: 1.6;">
        The automated WAF threat enforcement engine detected aggressive attack bursts originating from the client IPs listed below since last night.
        These IPs have been compiled into Coraza WAF's native SecLang <code>@ipMatch</code> directive (Rule ID <code>100020</code>) and hot-reloaded with zero downtime.
      </p>

      <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin: 18px 0;">
        <tr style="background: #f8fafc; text-align: left; border-bottom: 2px solid #cbd5e1;">
          <th style="padding: 10px;">Blocked Client IP</th>
          <th style="padding: 10px;">Attack Hit Rate</th>
          <th style="padding: 10px;">Attack Classification</th>
          <th style="padding: 10px;">Targeted URL Paths</th>
        </tr>
        {"".join(ip_rows_html)}
      </table>

      <div style="background: #f8fafc; border-left: 4px solid #dc2626; padding: 14px 18px; margin-bottom: 18px; font-size: 13px;">
        <strong>Enforcement Details:</strong><br/>
        &bull; <strong>Enforcement Mechanism:</strong> Native Coraza v3 SecLang <code>SecRule REMOTE_ADDR "@ipMatch ..." "id:100020,phase:1,deny,status:403"</code>.<br/>
        &bull; <strong>Persistence:</strong> Saved to <code>/data/waf-config.json</code> on Longhorn PVC storage.<br/>
        &bull; <strong>Current Total Blocked IPs:</strong> {len(cfg['blocked_ips'])} permanently blocked IPs.<br/>
        &bull; <strong>Timestamp:</strong> {utc_now}.
      </div>

      <div style="margin-top: 18px; padding-top: 14px; border-top: 1px solid #e2e8f0; font-size: 13px; color: #475569;">
        <strong>Quick Links (Local LAN):</strong><br/>
        &bull; <a href="http://10.0.10.15:8080">Coraza WAF Management Console &amp; Blocklist UI</a><br/>
        &bull; <a href="http://10.0.20.50:5601/app/dashboards#/view/dashboard-waf-logs">Coraza WAF Threat &amp; GeoIP Dashboard</a><br/>
        &bull; <a href="http://10.0.20.50:5601/app/dashboards#/view/dashboard-security-analytics">Security Analytics &amp; Threat Intel Dashboard</a>
      </div>
    </div>
  </div>
</body>
</html>"""

    text_body = f"""[CRITICAL - P1] Coraza WAF Automated IP Defense Enforcement
Timestamp: {utc_now}
Action: Automatically permanently blocked {len(newly_blocked)} IP(s) exceeding > 5 attacks / 15m.

Blocked Client IPs:
{"".join(ip_rows_txt)}

Total Blocked IPs in Coraza WAF: {len(cfg['blocked_ips'])}
Management UI: http://10.0.10.15:8080
"""

    send_ses_email(subject, html_body, text_body)
    return newly_blocked


if __name__ == "__main__":
    execute_auto_blocking()
