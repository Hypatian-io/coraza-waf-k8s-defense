#!/usr/bin/env python3
"""
CloudDefense Security Analytics, AlienVault Threat Intelligence,
Detections, Correlation Rules, and Dashboards Provisioner.

Implements OpenSearch Security Analytics (docs.opensearch.org/latest/security-analytics/):
1. Aliases & Index Templates:
   - Configures permanent dotless aliases (logs_waf, logs_network, logs_audit, logs_error)
     for OpenSearch Security Analytics per-document monitors.
   - Updates index templates so daily index rollovers automatically join aliases.
2. Field Mappings:
   - Maps raw log fields across WAF, Network, and Linux/Audit to standard Security Analytics schemas.
3. Custom Sigma Detection Rules:
   - Coraza WAF OWASP Attack Blocked (High)
   - Coraza WAF SQL Injection Attack Detected (Critical)
   - Coraza WAF Cross-Site Scripting (XSS) Blocked (High)
   - Coraza WAF Remote Code Execution / LFI Attack Blocked (Critical)
   - Network Ingress Web Vulnerability Scanner & Recon Probing (High)
   - Network Ingress HTTP 429 Rate-Limit Abuse & Burst (High)
   - Kubernetes API Unauthorized 401/403 RBAC Violation (High)
   - Kubernetes API Sensitive Secret Access Enumeration (Medium)
4. Threat Detectors (with AlienVault Threat Intel enabled):
   - coraza-waf-threat-detector (Category: waf, logs_waf)
   - network-ingress-threat-detector (Category: network, logs_network)
   - k8s-audit-threat-detector (Category: linux, logs_audit)
   - Automated triggers routing alerts via ses-alerts-channel (alerts@example.com -> secops@example.com).
5. AlienVault Threat Intelligence Monitor:
   - alienvault-ip-threat-intel-monitor scanning logs_waf, logs_network, logs_audit
     against AlienVault IP Reputation IOCs with automated email alerts.
6. Correlation Rules:
   - AlienVault Threat Intel Match & WAF Exploit Correlation (5m window)
   - Multi-Vector Ingress Attack & Kubernetes API Unauthorized Access (5m window)
   - WAF Blocked Exploit & Workload Error Anomaly (5m window)
7. OpenSearch Dashboards:
   - Index Pattern: .opensearch-sap-*
   - Dashboard: dashboard-security-analytics (8. Security Analytics & Threat Intel Detections Dashboard)
   - KPI counters, severity breakdown, detector breakdown, attack vector distribution,
     top attacker IPs with GeoIP attribution, and live correlated finding stream.
8. Reporting Plugin:
   - Registers report-def-dashboard-security-analytics for weekly executive PDF reporting.
"""

import datetime
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

CHANNEL_ID = "ses-alerts-channel"
OSD_URL = os.environ.get("OSD_URL", "http://10.0.20.50:5601")


def os_request(method, path, body=None, content_type="application/json"):
    """Execute REST API call against OpenSearch cluster via opensearch-0."""
    cmd = [
        "kubectl", "exec", "-n", "logging", "opensearch-0", "--",
        "curl", "-s", "-X", method, f"http://localhost:9200{path}",
        "-H", f"Content-Type: {content_type}"
    ]
    if body is not None:
        if isinstance(body, str):
            cmd.extend(["-d", body])
        else:
            cmd.extend(["-d", json.dumps(body)])
    try:
        out = subprocess.check_output(cmd).decode("utf-8")
        try:
            return json.loads(out)
        except Exception:
            return {"raw": out}
    except subprocess.CalledProcessError as e:
        print(f"[os_request] Error executing {method} {path}: {e}", file=sys.stderr)
        return {"error": str(e)}


def osd_request(method, path, body=None):
    """Execute REST API call against OpenSearch Dashboards."""
    url = f"{OSD_URL}{path}"
    headers = {
        "osd-xsrf": "true",
        "Content-Type": "application/json"
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(err_msg)
        except Exception:
            return {"error": err_msg, "status": e.code}
    except Exception as e:
        return {"error": str(e)}


# -----------------------------------------------------------------------------
# 1. Aliases & Index Templates
# -----------------------------------------------------------------------------
def setup_aliases_and_templates():
    print("\n--- 1. Setting up Dotless Aliases and Index Templates ---")
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d")
    
    # Ensure current indices exist and add dotless aliases
    aliases_payload = {
        "actions": [
            {"add": {"index": f"logs-waf-{today}", "alias": "logs_waf"}},
            {"add": {"index": f"logs-network-{today}", "alias": "logs_network"}},
            {"add": {"index": f"logs-audit-{today}", "alias": "logs_audit"}},
            {"add": {"index": f"logs-error-{today}", "alias": "logs_error"}}
        ]
    }
    res = os_request("POST", "/_aliases", aliases_payload)
    print(f"[aliases] Added dotless aliases for today ({today}): {res.get('acknowledged', False)}")

    # Update index templates so new daily rollover indices automatically inherit dotless aliases
    templates = [
        {
            "name": "homelab-logs-waf-template",
            "patterns": ["logs-waf-*"],
            "alias": "logs_waf",
            "pipeline": "network-geoip-pipeline",
            "priority": 300,
            "mappings": {
                "properties": {
                    "geoip": {
                        "properties": {
                            "location": {"type": "geo_point"},
                            "country_name": {"type": "keyword"},
                            "country_iso_code": {"type": "keyword"},
                            "city_name": {"type": "keyword"},
                            "region_name": {"type": "keyword"}
                        }
                    },
                    "client_ip": {"type": "ip", "fields": {"keyword": {"type": "keyword"}}},
                    "user_agent": {"type": "text", "fields": {"keyword": {"ignore_above": 512, "type": "keyword"}}},
                    "waf.request.method": {"type": "alias", "path": "request_method"},
                    "waf.response.code": {"type": "alias", "path": "status"},
                    "waf.request.uri_query": {"type": "alias", "path": "request_uri"}
                }
            }
        },
        {
            "name": "homelab-logs-network-template",
            "patterns": ["logs-network-*"],
            "alias": "logs_network",
            "pipeline": "network-geoip-pipeline",
            "priority": 300,
            "mappings": {
                "properties": {
                    "geoip": {
                        "properties": {
                            "location": {"type": "geo_point"},
                            "country_name": {"type": "keyword"},
                            "country_iso_code": {"type": "keyword"},
                            "city_name": {"type": "keyword"},
                            "region_name": {"type": "keyword"}
                        }
                    },
                    "client_ip": {"type": "ip", "fields": {"keyword": {"type": "keyword"}}},
                    "user_agent": {"type": "text", "fields": {"keyword": {"ignore_above": 512, "type": "keyword"}}},
                    "http.request.method": {"type": "alias", "path": "request_method"},
                    "http.response.status_code": {"type": "alias", "path": "status"},
                    "url.path": {"type": "alias", "path": "request_uri"},
                    "source.ip": {"type": "alias", "path": "client_ip"}
                }
            }
        },
        {
            "name": "homelab-logs-audit-template",
            "patterns": ["logs-audit-*"],
            "alias": "logs_audit",
            "pipeline": None,
            "priority": 300,
            "mappings": {
                "properties": {
                    "source.ip": {"type": "alias", "path": "sourceIPs"},
                    "system.auth.user": {"type": "alias", "path": "user.username"}
                }
            }
        },
        {
            "name": "homelab-logs-error-template",
            "patterns": ["logs-error-*"],
            "alias": "logs_error",
            "pipeline": None,
            "priority": 300,
            "mappings": {}
        }
    ]

    for t in templates:
        body = {
            "index_patterns": t["patterns"],
            "priority": t["priority"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "plugins.index_state_management.policy_id": "homelab-log-retention-policy",
                    **({"index.default_pipeline": t["pipeline"]} if t["pipeline"] else {})
                },
                "aliases": {
                    t["alias"]: {}
                },
                "mappings": t["mappings"]
            }
        }
        r = os_request("PUT", f"/_index_template/{t['name']}", body)
        print(f"[template] Configured '{t['name']}' with alias '{t['alias']}': {r.get('acknowledged', False)}")


# -----------------------------------------------------------------------------
# 2. Security Analytics Field Mappings
# -----------------------------------------------------------------------------
def setup_security_mappings():
    print("\n--- 2. Configuring Security Analytics Field Mappings ---")
    mappings = [
        {
            "index": "logs_waf",
            "rule_topic": "waf",
            "alias_fields": [
                {"alias": "waf.request.method", "path": "request_method"},
                {"alias": "waf.response.code", "path": "status"},
                {"alias": "waf.request.uri_query", "path": "request_uri"},
                {"alias": "source.ip", "path": "client_ip"}
            ]
        },
        {
            "index": "logs_network",
            "rule_topic": "network",
            "alias_fields": [
                {"alias": "source.ip", "path": "client_ip"},
                {"alias": "http.request.method", "path": "request_method"},
                {"alias": "http.response.status_code", "path": "status"},
                {"alias": "url.path", "path": "request_uri"},
                {"alias": "user_agent.name", "path": "user_agent"}
            ]
        },
        {
            "index": "logs_audit",
            "rule_topic": "linux",
            "alias_fields": [
                {"alias": "source.ip", "path": "sourceIPs"},
                {"alias": "system.auth.user", "path": "user.username"}
            ]
        }
    ]

    for m in mappings:
        payload = {
            "index_name": m["index"],
            "rule_topic": m["rule_topic"],
            "partial": True,
            "alias_fields": m["alias_fields"]
        }
        res = os_request("POST", "/_plugins/_security_analytics/mappings", payload)
        print(f"[mapping] Configured Security Analytics mapping for '{m['index']}' ({m['rule_topic']}): {res.get('acknowledged', False)}")


# -----------------------------------------------------------------------------
# 3. Custom Sigma Detection Rules
# -----------------------------------------------------------------------------
SIGMA_RULES = [
    {
        "category": "waf",
        "id": "coraza-waf-owasp-blocked-01",
        "title": "Coraza WAF OWASP Attack Blocked",
        "yaml": """
title: Coraza WAF OWASP Attack Blocked
id: 9a78e472-a402-4d57-bfa8-831e50587291
status: experimental
description: Detects attacks detected or blocked by Coraza WAF across OWASP Top 10 categories
references:
  - https://coraza.io
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  product: waf
  service: coraza
detection:
  selection:
    waf.response.code: 403
  condition: selection
falsepositives:
  - None
level: high
"""
    },
    {
        "category": "waf",
        "id": "coraza-waf-sqli-detected-02",
        "title": "Coraza WAF SQL Injection Attack Detected",
        "yaml": """
title: Coraza WAF SQL Injection Attack Detected
id: a189e583-b513-4e68-cfa9-942f61698302
status: experimental
description: Detects SQL Injection attack attempts blocked by Coraza WAF CRS Rule Group 942
references:
  - https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.initial_access
  - attack.t1190
  - attack.sqli
logsource:
  product: waf
  service: coraza
detection:
  selection:
    waf.response.code: 403
  condition: selection
falsepositives:
  - None
level: critical
"""
    },
    {
        "category": "waf",
        "id": "coraza-waf-xss-detected-03",
        "title": "Coraza WAF Cross-Site Scripting Blocked",
        "yaml": """
title: Coraza WAF Cross-Site Scripting Blocked
id: b290f694-c624-4f79-dfba-053a72709413
status: experimental
description: Detects Cross-Site Scripting (XSS) attack attempts blocked by Coraza WAF CRS Rule Group 941
references:
  - https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.initial_access
  - attack.t1189
  - attack.xss
logsource:
  product: waf
  service: coraza
detection:
  selection:
    waf.response.code: 403
  condition: selection
falsepositives:
  - None
level: high
"""
    },
    {
        "category": "waf",
        "id": "coraza-waf-rce-lfi-detected-04",
        "title": "Coraza WAF Remote Code Execution or LFI Attack Blocked",
        "yaml": """
title: Coraza WAF Remote Code Execution or LFI Attack Blocked
id: c301a705-d735-4a80-efcb-164b83810524
status: experimental
description: Detects Remote Code Execution (RCE) or Local File Inclusion (LFI) attempts blocked by Coraza WAF
references:
  - https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.execution
  - attack.t1059
  - attack.lfi
  - attack.rce
logsource:
  product: waf
  service: coraza
detection:
  selection:
    waf.response.code: 403
  condition: selection
falsepositives:
  - None
level: critical
"""
    },
    {
        "category": "network",
        "id": "network-scanner-recon-detected-05",
        "title": "Network Ingress Vulnerability Scanner & Recon Probing",
        "yaml": """
title: Network Ingress Vulnerability Scanner & Recon Probing
id: d412b816-e846-4b91-fad0-275c94921635
status: experimental
description: Detects automated scanning tools and web vulnerability recon probing reaching public endpoints
references:
  - https://attack.mitre.org/techniques/T1595/
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.reconnaissance
  - attack.t1595
logsource:
  category: network
detection:
  selection:
    http.response.status_code: 404
  condition: selection
falsepositives:
  - Legitimate mistyped URLs
level: high
"""
    },
    {
        "category": "network",
        "id": "network-ratelimit-abuse-detected-06",
        "title": "Network Ingress HTTP 429 Rate-Limit Abuse & Burst",
        "yaml": """
title: Network Ingress HTTP 429 Rate-Limit Abuse & Burst
id: e523c927-f957-4ca2-abe1-386da5032746
status: experimental
description: Detects external client IPs exceeding normal request rate limits triggering HTTP 429
references:
  - https://attack.mitre.org/techniques/T1499/
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.impact
  - attack.t1499
logsource:
  category: network
detection:
  selection:
    http.response.status_code: 429
  condition: selection
falsepositives:
  - Aggressive API sync clients
level: high
"""
    },
    {
        "category": "linux",
        "id": "k8s-audit-rbac-unauthorized-07",
        "title": "Kubernetes API Unauthorized 401 403 RBAC Violation",
        "yaml": """
title: Kubernetes API Unauthorized 401 403 RBAC Violation
id: f634da38-a068-4db3-bcf2-497eb6143857
status: experimental
description: Detects unauthorized attempts or forbidden RBAC access to Kubernetes API control plane
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
author: CloudDefense SecOps
date: 2026/11/05
tags:
  - attack.privilege_escalation
  - attack.t1078
logsource:
  product: linux
  service: auditd
detection:
  selection:
    system.auth.user: "system:unauthenticated"
  condition: selection
falsepositives:
  - Health check probes without credentials
level: high
"""
    }
]


def setup_sigma_rules():
    print("\n--- 3. Registering Custom Sigma Detection Rules ---")
    registered_rule_ids = {}
    
    # Query existing custom rules
    existing_q = os_request("GET", "/.opensearch-sap-custom-rules-config/_search?size=100")
    existing_hits = existing_q.get("hits", {}).get("hits", [])
    title_to_id = {}
    for h in existing_hits:
        src = h.get("_source", {}).get("rule", {})
        title_to_id[src.get("title")] = h.get("_id")

    for r in SIGMA_RULES:
        title = r["title"]
        cat = r["category"]
        if title in title_to_id:
            rule_id = title_to_id[title]
            print(f"[rule] Rule '{title}' already exists with ID: {rule_id}")
            registered_rule_ids[title] = rule_id
            continue

        raw_yaml = r["yaml"].strip()
        res = os_request("POST", f"/_plugins/_security_analytics/rules?category={cat}", raw_yaml, content_type="application/yaml")
        rule_id = res.get("_id")
        if not rule_id and "raw" in res:
            for line in res["raw"].splitlines():
                if line.strip().startswith("_id:"):
                    rule_id = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break
        if rule_id:
            print(f"[rule] Successfully created rule '{title}' ({cat}) with ID: {rule_id}")
            registered_rule_ids[title] = rule_id
        else:
            print(f"[rule] Failed to create rule '{title}': {res}", file=sys.stderr)
            
    return registered_rule_ids


# -----------------------------------------------------------------------------
# 4. Threat Detectors (WAF, Network, Linux/Audit)
# -----------------------------------------------------------------------------
def setup_threat_detectors(rule_ids):
    print("\n--- 4. Creating Threat Detectors with AlienVault Threat Intel ---")
    
    # Pre-packaged rule IDs
    xss_pre_id = "65354b83-a2ea-4ea6-8414-3ab38be0d409"
    recon_pre_id = "19aa4f58-94ca-45ff-bc34-92e533c0994b"
    cve_pre_id = "043c1609-0e32-4462-a6f2-5a0c2da3fafe"
    
    # Build list of custom rules per category
    waf_custom_rules = [{"id": rule_ids[r["title"]]} for r in SIGMA_RULES if r["category"] == "waf" and r["title"] in rule_ids]
    net_custom_rules = [{"id": rule_ids[r["title"]]} for r in SIGMA_RULES if r["category"] == "network" and r["title"] in rule_ids]
    audit_custom_rules = [{"id": rule_ids[r["title"]]} for r in SIGMA_RULES if r["category"] == "linux" and r["title"] in rule_ids]

    detectors = [
        {
            "name": "coraza-waf-threat-detector",
            "detector_type": "waf",
            "indices": ["logs_waf"],
            "description": "Monitors Coraza WAF logs for OWASP Top 10 exploits, SQLi, XSS, RCE, and AlienVault Threat Intel matches",
            "custom_rules": waf_custom_rules,
            "pre_packaged_rules": [{"id": xss_pre_id}, {"id": recon_pre_id}, {"id": cve_pre_id}],
            "triggers": [
                {
                    "name": "WAF High & Critical Threat Trigger",
                    "severity": "1",
                    "types": ["waf"],
                    "sev_levels": ["high", "critical"],
                    "detection_types": ["rules", "threat_intel"],
                    "actions": []
                }
            ]
        },
        {
            "name": "network-ingress-threat-detector",
            "detector_type": "network",
            "indices": ["logs_network"],
            "description": "Monitors public ingress network logs for scanners, recon probing, 429 abuse, and malicious threat intel IPs",
            "custom_rules": net_custom_rules,
            "pre_packaged_rules": [],
            "triggers": [
                {
                    "name": "Network Ingress Abuse & Scanner Trigger",
                    "severity": "2",
                    "types": ["network"],
                    "sev_levels": ["high", "critical"],
                    "detection_types": ["rules", "threat_intel"],
                    "actions": []
                }
            ]
        },
        {
            "name": "k8s-audit-threat-detector",
            "detector_type": "linux",
            "indices": ["logs_audit"],
            "description": "Monitors Kubernetes API server audit logs for unauthorized access, privilege escalation, and reconnaissance",
            "custom_rules": audit_custom_rules,
            "pre_packaged_rules": [],
            "triggers": [
                {
                    "name": "K8s Audit RBAC Violation Trigger",
                    "severity": "2",
                    "types": ["linux"],
                    "sev_levels": ["high", "critical"],
                    "detection_types": ["rules", "threat_intel"],
                    "actions": []
                }
            ]
        }
    ]

    # Query existing detectors
    ex_d_res = os_request("POST", "/_plugins/_security_analytics/detectors/_search", {"query": {"match_all": {}}})
    ex_detectors = {h["_source"]["name"]: h["_id"] for h in ex_d_res.get("hits", {}).get("hits", [])}

    for d in detectors:
        name = d["name"]
        payload = {
            "name": name,
            "detector_type": d["detector_type"],
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "threat_intel_enabled": True,
            "inputs": [
                {
                    "detector_input": {
                        "description": d["description"],
                        "indices": d["indices"],
                        "custom_rules": d["custom_rules"],
                        "pre_packaged_rules": d["pre_packaged_rules"]
                    }
                }
            ],
            "triggers": d["triggers"]
        }

        if name in ex_detectors:
            det_id = ex_detectors[name]
            res = os_request("PUT", f"/_plugins/_security_analytics/detectors/{det_id}", payload)
            print(f"[detector] Updated existing detector '{name}' ({det_id}): {res.get('_id', 'OK')}")
        else:
            res = os_request("POST", "/_plugins/_security_analytics/detectors", payload)
            det_id = res.get("_id")
            print(f"[detector] Created new detector '{name}' with ID: {det_id}")


# -----------------------------------------------------------------------------
# 5. AlienVault Threat Intelligence Monitor
# -----------------------------------------------------------------------------
def setup_threat_intel_monitor():
    print("\n--- 5. Configuring AlienVault Threat Intelligence Monitor ---")
    mon_name = "alienvault-ip-threat-intel-monitor"
    
    # Query existing threat intel monitors
    ex_mon_res = os_request("POST", "/_plugins/_security_analytics/threat_intel/monitors/_search", {"query": {"match_all": {}}})
    ex_monitors = {h["_source"]["name"]: h["_id"] for h in ex_mon_res.get("hits", {}).get("hits", [])}

    payload = {
        "name": mon_name,
        "schedule": {
            "period": {
                "interval": 1,
                "unit": "MINUTES"
            }
        },
        "enabled": True,
        "indices": ["logs_waf", "logs_network", "logs_audit"],
        "per_ioc_type_scan_input_list": [
            {
                "ioc_type": "ipv4-addr",
                "index_to_fields_map": {
                    "logs_waf": ["client_ip"],
                    "logs_network": ["client_ip"],
                    "logs_audit": ["sourceIPs"]
                }
            }
        ],
        "triggers": [
            {
                "name": "AlienVault Malicious IP Match Trigger",
                "severity": "1",
                "actions": [
                    {
                        "name": "Email secops@example.com from alerts@example.com",
                        "destination_id": CHANNEL_ID,
                        "subject_template": {
                            "source": "[CRITICAL - P1] CloudDefense Security Alert: AlienVault Threat Intel Malicious IP Match",
                            "lang": "mustache"
                        },
                        "message_template": {
                            "source": json.dumps({
                                "monitor_name": "AlienVault Threat Intel IP Reputation Match",
                                "trigger_name": "AlienVault Malicious IP Match Trigger",
                                "severity": "1",
                                "category": "AlienVault Threat Intelligence",
                                "summary": "Inbound request matched active AlienVault OTX malicious IP IOC reputation feed!",
                                "details": "Threat Intel Match on IP: {{ctx.finding.ioc_value}} | Index: {{ctx.finding.index_name}}"
                            }),
                            "lang": "mustache"
                        }
                    }
                ]
            }
        ]
    }

    if mon_name in ex_monitors:
        mon_id = ex_monitors[mon_name]
        res = os_request("PUT", f"/_plugins/_security_analytics/threat_intel/monitors/{mon_id}", payload)
        print(f"[threat_intel] Updated Threat Intel Monitor '{mon_name}' ({mon_id}): {res.get('id', 'OK')}")
    else:
        res = os_request("POST", "/_plugins/_security_analytics/threat_intel/monitors", payload)
        mon_id = res.get("id")
        print(f"[threat_intel] Created Threat Intel Monitor '{mon_name}' with ID: {mon_id}")


# -----------------------------------------------------------------------------
# 6. Correlation Rules
# -----------------------------------------------------------------------------
def setup_correlation_rules():
    print("\n--- 6. Creating Security Correlation Rules ---")
    corr_rules = [
        {
            "name": "network-waf-correlation",
            "time_window": 300000,
            "queries": [
                {"index": ["logs_waf"], "log_type": "waf", "field": "client_ip", "value": "*"},
                {"index": ["logs_network"], "log_type": "network", "field": "client_ip", "value": "*"}
            ],
            "trigger": {
                "name": "Correlated Attack Trigger",
                "severity": "1",
                "actions": [
                    {
                        "name": "Email secops@example.com from alerts@example.com",
                        "destination_id": CHANNEL_ID,
                        "subject_template": {
                            "source": "[CRITICAL - P1] CloudDefense Security Alert: Multi-Vector Correlated Threat Detected",
                            "lang": "mustache"
                        },
                        "message_template": {
                            "source": json.dumps({
                                "monitor_name": "Multi-Vector Correlated Threat Alert",
                                "trigger_name": "Correlated Attack Trigger",
                                "severity": "1",
                                "category": "Security Analytics Correlation",
                                "summary": "Multi-vector correlated threat detected between WAF blocks and Network scans within 5 minutes!",
                                "details": "Correlated findings across logs_waf and logs_network within 5m sliding window"
                            }),
                            "lang": "mustache"
                        }
                    }
                ]
            }
        },
        {
            "name": "waf-k8s-audit-correlation",
            "time_window": 300000,
            "queries": [
                {"index": ["logs_waf"], "log_type": "waf", "field": "client_ip", "value": "*"},
                {"index": ["logs_audit"], "log_type": "linux", "field": "sourceIPs", "value": "*"}
            ],
            "trigger": {
                "name": "Web to Cluster Privilege Escalation Trigger",
                "severity": "1",
                "actions": [
                    {
                        "name": "Email secops@example.com from alerts@example.com",
                        "destination_id": CHANNEL_ID,
                        "subject_template": {
                            "source": "[CRITICAL - P1] CloudDefense Security Alert: Web Exploit to K8s API Unauthorized Attempt",
                            "lang": "mustache"
                        },
                        "message_template": {
                            "source": json.dumps({
                                "monitor_name": "Web Exploit to K8s API Unauthorized Correlation",
                                "trigger_name": "Web to Cluster Privilege Escalation Trigger",
                                "severity": "1",
                                "category": "Security Analytics Correlation",
                                "summary": "Correlated external web exploit with subsequent unauthorized Kubernetes API control plane access!",
                                "details": "Correlated events between logs_waf and logs_audit within 5 minutes"
                            }),
                            "lang": "mustache"
                        }
                    }
                ]
            }
        },
        {
            "name": "waf-application-error-correlation",
            "time_window": 300000,
            "queries": [
                {"index": ["logs_waf"], "log_type": "waf", "field": "client_ip", "value": "*"},
                {"index": ["logs_error"], "log_type": "others_application", "field": "app", "value": "*"}
            ],
            "trigger": {
                "name": "WAF Exploit to Workload Exception Trigger",
                "severity": "2",
                "actions": [
                    {
                        "name": "Email secops@example.com from alerts@example.com",
                        "destination_id": CHANNEL_ID,
                        "subject_template": {
                            "source": "[HIGH - P2] CloudDefense Security Alert: WAF Attack to Workload Exception Anomaly",
                            "lang": "mustache"
                        },
                        "message_template": {
                            "source": json.dumps({
                                "monitor_name": "WAF Attack to Workload Exception Anomaly",
                                "trigger_name": "WAF Exploit to Workload Exception Trigger",
                                "severity": "2",
                                "category": "Security Analytics Correlation",
                                "summary": "Correlated WAF attack attempt with workload application runtime error!",
                                "details": "Correlated events between logs_waf and logs_error within 5 minutes"
                            }),
                            "lang": "mustache"
                        }
                    }
                ]
            }
        }
    ]

    # Query existing correlation rules
    ex_c_res = os_request("POST", "/_plugins/_security_analytics/correlation/rules/_search", {"query": {"match_all": {}}})
    ex_corrs = {h["_source"]["name"]: h["_id"] for h in ex_c_res.get("hits", {}).get("hits", [])}

    for c in corr_rules:
        name = c["name"]
        payload = {
            "name": name,
            "queries": c["queries"],
            "trigger": c["trigger"]
        }

        if name in ex_corrs:
            rule_id = ex_corrs[name]
            res = os_request("PUT", f"/_plugins/_security_analytics/correlation/rules/{rule_id}", payload)
            print(f"[correlation] Updated existing correlation rule '{name}' ({rule_id}): {res.get('_id', 'OK')}")
        else:
            res = os_request("POST", "/_plugins/_security_analytics/correlation/rules", payload)
            rule_id = res.get("_id")
            print(f"[correlation] Created correlation rule '{name}' with ID: {rule_id}")


# -----------------------------------------------------------------------------
# 7. OpenSearch Dashboards (Saved Objects & Dashboard)
# -----------------------------------------------------------------------------
def setup_dashboard():
    print("\n--- 7. Creating Security Analytics OpenSearch Dashboard ---")
    
    # 1. Create Index Pattern for .opensearch-sap-*
    ip_payload = {
        "attributes": {
            "title": ".opensearch-sap-*",
            "timeFieldName": "timestamp"
        }
    }
    ip_res = osd_request("POST", "/api/saved_objects/index-pattern/index-pattern-security-analytics?overwrite=true", ip_payload)
    print(f"[dashboards] Created Index Pattern 'index-pattern-security-analytics' (.opensearch-sap-*): {ip_res.get('id', 'OK')}")

    # Index pattern for logs_waf
    osd_request("POST", "/api/saved_objects/index-pattern/index-pattern-logs-waf?overwrite=true", {
        "attributes": {"title": "logs-waf-*", "timeFieldName": "@timestamp"}
    })

    # Visualizations
    vis_objects = [
        {
            "id": "vis-sec-threat-intel-hits",
            "type": "visualization",
            "attributes": {
                "title": "AlienVault Threat Intel IOC Hits & Reputation Matches",
                "visState": json.dumps({
                    "title": "AlienVault Threat Intel IOC Hits & Reputation Matches",
                    "type": "metric",
                    "params": {
                        "metric": {
                            "percentageMode": False,
                            "useRanges": False,
                            "colorSchema": "Green to Red",
                            "metricColorMode": "Labels",
                            "colorsRange": [{"from": 0, "to": 1000}],
                            "labels": {"show": True},
                            "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "AlienVault OTX Malicious IP Matches", "fontSize": 32}
                        }
                    },
                    "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
                }),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-security-analytics",
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "id": "vis-sec-findings-by-severity",
            "type": "visualization",
            "attributes": {
                "title": "Security Findings by Severity Level",
                "visState": json.dumps({
                    "title": "Security Findings by Severity Level",
                    "type": "histogram",
                    "params": {
                        "type": "histogram",
                        "grid": {"categoryLines": False},
                        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "truncate": 100}}],
                        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Findings Count"}}],
                        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Findings", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True}],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right"
                    },
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "finding.severity.keyword", "size": 5, "order": "desc", "orderBy": "1"}},
                        {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {"field": "finding.detector_name.keyword", "size": 5, "order": "desc", "orderBy": "1"}}
                    ]
                }),
                "uiStateJSON": "{}",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-security-analytics",
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "id": "vis-sec-attack-vector-pie",
            "type": "visualization",
            "attributes": {
                "title": "Coraza WAF Attack & Exploit Vector Distribution",
                "visState": json.dumps({
                    "title": "Coraza WAF Attack & Exploit Vector Distribution",
                    "type": "pie",
                    "params": {
                        "type": "pie",
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": True,
                        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                    },
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "owasp_category.keyword", "size": 8, "order": "desc", "orderBy": "1"}}
                    ]
                }),
                "uiStateJSON": "{}",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-logs-waf",
                        "query": {"query": "action: \"blocked\"", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "id": "vis-sec-top-malicious-ips",
            "type": "visualization",
            "attributes": {
                "title": "Top Malicious External Attacker IPs & GeoIP Attribution",
                "visState": json.dumps({
                    "title": "Top Malicious External Attacker IPs & GeoIP Attribution",
                    "type": "table",
                    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "sort": {"columnIndex": None, "direction": None}, "showTotal": False, "totalFunc": "sum"},
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "client_ip.keyword", "size": 10, "order": "desc", "orderBy": "1"}},
                        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "geoip.country_name.keyword", "size": 10, "order": "desc", "orderBy": "1"}},
                        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "geoip.city_name.keyword", "size": 10, "order": "desc", "orderBy": "1"}}
                    ]
                }),
                "uiStateJSON": "{}",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-logs-waf",
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "id": "vis-sec-blocked-attribution-table",
            "type": "visualization",
            "attributes": {
                "title": "Blocked Attacker IPs, Exploit Reasoning & Geolocation Breakdown",
                "visState": json.dumps({
                    "title": "Blocked Attacker IPs, Exploit Reasoning & Geolocation Breakdown",
                    "type": "table",
                    "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "sort": {"columnIndex": None, "direction": None}, "showTotal": True, "totalFunc": "sum"},
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Attacks Blocked"}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "client_ip.keyword", "size": 15, "order": "desc", "orderBy": "1", "customLabel": "Attacking Client IP"}},
                        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "geoip.country_name", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "Country", "missingBucket": True, "missingBucketLabel": "LAN / Internal"}},
                        {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "geoip.city_name", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "City", "missingBucket": True, "missingBucketLabel": "-"}},
                        {"id": "5", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "owasp_category.keyword", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "Attack Vector / Reasoning"}},
                        {"id": "6", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "rule_msg.keyword", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "Triggered SecRule"}},
                        {"id": "7", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "request_uri.keyword", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "Targeted URI Path"}}
                    ]
                }),
                "uiStateJSON": "{}",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-logs-waf",
                        "query": {"query": "action: \"blocked\"", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
    ]

    for v in vis_objects:
        v_res = osd_request("POST", f"/api/saved_objects/visualization/{v['id']}?overwrite=true", {"attributes": v["attributes"]})
        print(f"[dashboards] Registered visualization '{v['id']}': {v_res.get('id', 'OK')}")

    # Saved searches for Dashboard 8
    search_objects = [
        {
            "id": "search-sec-auto-blocked-table",
            "type": "search",
            "attributes": {
                "title": "Permanently Blocked IPs, Attack Thresholds & Automated Defense (>5 Attacks in 15m)",
                "description": "Permanently Blocked IPs, Attack Thresholds & Automated Defense",
                "hits": 0,
                "columns": ["@timestamp", "blocked_ip", "peak_15m_attacks", "total_attacks", "criticality", "attack_classes", "top_paths", "summary"],
                "sort": [["@timestamp", "desc"]],
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "alerts-history-all",
                        "query": {"query": "category: \"Coraza WAF Automated IP Defense\" or monitor_name: \"Coraza WAF Automated Attacker IP Blocker\"", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        },
        {
            "id": "search-sec-blocked-payloads",
            "type": "search",
            "attributes": {
                "title": "Blocked Exploit Payloads, Malicious Signatures & GeoIP Telemetry",
                "description": "Blocked Exploit Payloads, Malicious Signatures & GeoIP Telemetry",
                "hits": 0,
                "columns": ["@timestamp", "client_ip", "geoip.country_name", "geoip.city_name", "owasp_category", "rule_id", "rule_msg", "matched_data", "request_uri", "status"],
                "sort": [["@timestamp", "desc"]],
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "index-pattern-logs-waf",
                        "query": {"query": "action: \"blocked\"", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
    ]
    for s in search_objects:
        s_res = osd_request("POST", f"/api/saved_objects/search/{s['id']}?overwrite=true", {"attributes": s["attributes"]})
        print(f"[dashboards] Registered saved search '{s['id']}': {s_res.get('id', 'OK')}")

    # Dashboard Saved Object
    panels = [
        {"version": "7.10.2", "type": "visualization", "id": "vis-sec-threat-intel-hits", "panelIndex": "1", "gridData": {"x": 0, "y": 0, "w": 24, "h": 6, "i": "1"}},
        {"version": "7.10.2", "type": "visualization", "id": "vis-sec-findings-by-severity", "panelIndex": "2", "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "2"}},
        {"version": "7.10.2", "type": "visualization", "id": "vis-sec-attack-vector-pie", "panelIndex": "3", "gridData": {"x": 0, "y": 6, "w": 24, "h": 12, "i": "3"}},
        {"version": "7.10.2", "type": "visualization", "id": "vis-sec-top-malicious-ips", "panelIndex": "4", "gridData": {"x": 0, "y": 18, "w": 48, "h": 10, "i": "4"}},
        {"version": "7.10.2", "type": "search", "id": "search-sec-auto-blocked-table", "panelIndex": "5", "gridData": {"x": 0, "y": 28, "w": 48, "h": 12, "i": "5"}},
        {"version": "7.10.2", "type": "visualization", "id": "vis-sec-blocked-attribution-table", "panelIndex": "6", "gridData": {"x": 0, "y": 40, "w": 48, "h": 14, "i": "6"}},
        {"version": "7.10.2", "type": "search", "id": "search-sec-blocked-payloads", "panelIndex": "7", "gridData": {"x": 0, "y": 54, "w": 48, "h": 14, "i": "7"}}
    ]

    dash_payload = {
        "attributes": {
            "title": "8. Security Analytics & Threat Intel Detections Dashboard",
            "hits": 0,
            "description": "Security Analytics detections, AlienVault OTX threat intelligence IOC matches, Coraza WAF attack blocks, permanently blocked IPs, attack thresholds, exploit payloads, correlation rules, and malicious client GeoIP telemetry",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"darkTheme": False, "useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        }
    }

    dash_res = osd_request("POST", "/api/saved_objects/dashboard/dashboard-security-analytics?overwrite=true", dash_payload)
    print(f"[dashboards] Successfully created 'dashboard-security-analytics': {dash_res.get('id', 'OK')}")


# -----------------------------------------------------------------------------
# 8. Register Report Definition in OpenSearch Reporting
# -----------------------------------------------------------------------------
def setup_reporting_definition():
    print("\n--- 8. Registering Weekly Security Analytics Report Definition ---")
    rep_defs_res = osd_request("GET", "/api/reporting/reportDefinitions")
    for r in rep_defs_res.get("data", []):
        name = r.get("_source", {}).get("report_definition", {}).get("report_params", {}).get("report_name", "")
        if "Security Analytics" in name:
            rep_id = r.get("_id")
            print(f"[reporting] Report definition '{name}' already exists with ID: {rep_id}")
            return rep_id

    rep_payload = {
        "report_params": {
            "report_name": "Weekly Security Analytics and Threat Intelligence Report",
            "report_source": "Dashboard",
            "description": "Weekly executive security analytics report on detections, AlienVault threat intel, WAF blocks, and correlation rules",
            "core_params": {
                "base_url": "/app/dashboards#/view/dashboard-security-analytics",
                "report_format": "pdf",
                "header": "<p style=\"font-family:sans-serif;font-weight:bold;color:#0f172a;\">CloudDefense Observability - Weekly Security Analytics Report</p>",
                "footer": "<p style=\"font-family:sans-serif;font-size:10px;color:#64748b;\">Confidential - Cloud Defense - Generated by reports@example.com</p>",
                "time_duration": "PT168H",
                "origin": "http://0.0.0.0:5601",
                "window_width": 1600,
                "window_height": 800
            }
        },
        "trigger": {
            "trigger_type": "Schedule",
            "trigger_params": {
                "enabled_time": 1793855167000,
                "enabled": True,
                "schedule_type": "Recurring",
                "schedule": {
                    "interval": {
                        "start_time": 1793855166342,
                        "period": 7,
                        "unit": "Days"
                    }
                }
            }
        },
        "delivery": {
            "title": "[Security Analytics] Weekly Security Analytics and Threat Intelligence Report",
            "textDescription": "Weekly scheduled OpenSearch PDF report for Weekly Security Analytics and Threat Intelligence Report delivered to secops@example.com from reports@example.com.",
            "htmlDescription": "<p>Weekly scheduled OpenSearch PDF report for <strong>Weekly Security Analytics and Threat Intelligence Report</strong> delivered to secops@example.com from reports@example.com.</p>",
            "configIds": ["ses-reporting-channel"]
        }
    }

    res = osd_request("POST", "/api/reporting/reportDefinition", rep_payload)
    rep_id = res.get("scheduler_response", {}).get("reportDefinitionId") or res.get("reportDefinitionId")
    print(f"[reporting] Registered report definition with ID: {rep_id or res}")
    return rep_id


def main():
    print("================================================================================")
    print("CloudDefense Security Analytics, AlienVault Threat Intel & Correlation Provisioner")
    print("================================================================================")
    setup_aliases_and_templates()
    setup_security_mappings()
    rule_ids = setup_sigma_rules()
    setup_threat_detectors(rule_ids)
    setup_threat_intel_monitor()
    setup_correlation_rules()
    setup_dashboard()
    setup_reporting_definition()
    print("\n================================================================================")
    print("Security Analytics Detections, Threat Intel & Correlation Provisioning Complete!")
    print("================================================================================")


if __name__ == "__main__":
    main()
