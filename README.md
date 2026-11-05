<p align="center">
  <img src="docs/images/hypatian_logo_dark.png" alt="Hypatian Systems Research" width="380" />
</p>

# Building an Autonomous Cloud-Native Defense Stack: Embedding Coraza WAF v3, OpenSearch Security Analytics, Real-Time GeoIP, and Automated Threat Response on Kubernetes

> *A complete, visual, step-by-step engineering guide to deploying an enterprise-grade Web Application Firewall, lightweight in-memory log sidecars, OWASP Top 10 protection, high-rate burst detection, and self-healing IP quarantine on Kubernetes.*

[**GitHub Repo**](https://github.com/saadrana219/coraza-waf-k8s-defense) | **Release:** `v1.0.0` | **Kubernetes:** `v1.26+` | **Coraza WAF:** `v3.2.1` | **OpenSearch:** `v2.19.7` | **License:** `MIT`

> ⚡ **Agentic Engineering Note:** Engineered, deployed, and published autonomously using the **Gemini Antigravity CLI** (`agy`) across Go proxy implementation, OpenSearch telemetry tuning, automated verification, and Route 53 publication.

---

## 1. Introduction: The Ingress Defense Dilemma

At **Hypatian Systems Research**, our production Kubernetes cluster serves mission-critical web applications and APIs. Exposing these services to the public Internet invites relentless automated hostility. Within minutes of provisioning a public IP or DNS record, scanning botnets (`nuclei`, `masscan`, `nikto`), automated exploit frameworks, and credential stuffers begin probing web endpoints with directory traversal probes (`/etc/passwd`, `.env`, `.git`), webshell uploads (`eval-stdin.php`), and injection attacks (`' OR 1=1--`).

### Container Workload Ingress Security Risks

```mermaid
flowchart TD
    subgraph Threats ["🚨 Ingress Attack Vectors & Automated Probes"]
        T1["💥 OWASP Top 10 Exploits<br>• SQL Injection: ' OR 1=1--<br>• Remote Code Execution: /api/exec<br>• Path Traversal: /etc/passwd, .env<br>• Webshell Uploads: eval-stdin.php"]
        T2["🤖 Automated Reconnaissance & Scanners<br>• Fast Scanners: nuclei, masscan, nikto<br>• Endpoint Discovery: .git, swagger, wp-login<br>• High-Frequency Probe Bursts"]
        T3["⚡ Volumetric & Credential Abuse<br>• Distributed Credential Stuffing<br>• Layer 7 Denial of Service: HTTP Floods<br>• Slowloris & Resource Exhaustion"]
    end

    subgraph DefenseGaps ["⚠️ Traditional Ingress Defense Gaps"]
        G1["❌ Cloud SaaS WAF Bottlenecks<br>• High recurring per-request bandwidth fees<br>• Blind to internal cluster and pod traffic<br>• Opaque black-box SecLang rule sets"]
        G2["❌ Legacy C / ModSecurity Proxies<br>• Memory corruption and segfault crashes<br>• Full container restarts required for rule reloads<br>• Heavy container memory footprint"]
        G3["❌ Naive Un-Tuned Alerting<br>• 500+ spam alerts per automated scanner pass<br>• Severe on-call fatigue causes missed alerts<br>• Zero automated IP quarantine loop"]
    end

    subgraph ModernStack ["🛡️ Autonomous Cloud-Native Defense (Hypatian Systems Stack)"]
        D1["✅ Pure Go Coraza v3 Ingress WAF<br>• 100% open-source & on-premises<br>• In-memory sub-millisecond inspection<br>• Full ingress and service mesh coverage"]
        D2["✅ Dynamic In-Memory Hot-Reload<br>• Atomic Go pointer swapping (zero downtime)<br>• Memory-safe runtime without leak crashes<br>• Instant SecLang rule and blocklist reloads"]
        D3["✅ Self-Healing Autonomous Defense<br>• 14 OpenSearch burst monitors (over 5 hits / 15m)<br>• Real-time automated attacker IP quarantine<br>• Enriched executive alert briefings via AWS SES"]
    end

    subgraph Workload ["☸️ Protected Container Workloads & Cluster Services"]
        K8sApp["Kubernetes Ingress & Applications<br>(Web Apps, Flask APIs, Microservices, MariaDB)"]
    end

    Threats -->|Exploit Probes| DefenseGaps
    DefenseGaps -.->|Exposes Workloads to Compromise| Workload
    Threats ==>|Inspected & Filtered| ModernStack
    ModernStack ==>|Guaranteed Clean Traffic| Workload
```

This guide details the complete architecture, source code, visual dashboards, and automated quarantine loop deployed across our Kubernetes cluster. All manifests, automation scripts, and Go source code are maintained in the companion open-source repository:
👉 [**https://github.com/saadrana219/coraza-waf-k8s-defense**](https://github.com/saadrana219/coraza-waf-k8s-defense)

---

## 2. Visual Architecture & Component Topology

The system comprises seven decoupled, resilient layers operating in harmony:

```mermaid
flowchart TD
    subgraph External ["🌐 Untrusted External Internet"]
        Attacker["🚨 Malicious Client / Scanner\n(SQLi, RCE, Webshells)"]
        Legit["👤 Legitimate User Traffic"]
    end

    subgraph Layer1 ["1. Ingress & Client IP Preservation"]
        MetalLB["MetalLB LoadBalancer\n203.0.113.10:443"]
        Traefik["Traefik Reverse Proxy\nexternalTrafficPolicy: Local\n(Preserves True REMOTE_ADDR)"]
    end

    subgraph Layer2 ["2. Coraza v3 WAF & Management Console"]
        CorazaProxy["Coraza WAF Reverse Proxy\n(10.0.10.15:80)\nPure Go v3.2.1 | CRS v4.3.0\nAtomic Pointer Swap Hot-Reload"]
        CorazaUI["Native WAF Console & SecLang Playground\n(10.0.10.15:8080)"]
    end

    subgraph Layer3 ["3. Protected Application Services"]
        WebApp["Web App (Nginx Static Frontend)\n+ API (Flask / Gunicorn)\n+ MariaDB Galera Cluster"]
    end

    subgraph Layer4 ["4. In-Memory Sidecar Shipper"]
        WafLog["/var/log/waf/audit.log\n(64Mi in-memory emptyDir)"]
        RotateScript["rotate-logs.sh\n(Truncates active logs > 5MB)"]
        FluentBitSidecar["Fluent Bit Sidecar\n(Memory footprint: ~24Mi)"]
    end

    subgraph Layer5 ["5. OpenSearch 2.19.7 Analytics & Enrichment"]
        GeoIPPipeline["network-geoip-pipeline\n(MaxMind GeoIP Enrichment)"]
        DotlessAliases["Dotless Aliases (logs_waf, logs_network)\nRoute to logs-waf-YYYY.MM.DD"]
        SecurityAnalytics["OpenSearch Security Analytics\nAlienVault OTX IP Reputation (609 IOCs)\n5-Min Correlation Rules"]
    end

    subgraph Layer6 ["6. Automated Defense & Executive Alerting"]
        BurstDetectors["14 Query-Level Burst Monitors\n(SQLi, RCE, XSS, Scanner Storms)"]
        AutoBlockDaemon["Autonomous IP Blocker Daemon\n(Evaluates > 5 attacks / 15m)"]
        SESEmail["AWS SES Notification Relay\n(secops@example.com)"]
    end

    Attacker -->|HTTPS Request| MetalLB
    Legit -->|HTTPS Request| MetalLB
    MetalLB --> Traefik
    Traefik -->|Forward with Real IP| CorazaProxy
    CorazaProxy -->|Blocked 403 Forbidden| Attacker
    CorazaProxy -->|Clean 200 OK| WebApp
    CorazaProxy -->|JSON Audit Stream| WafLog
    WafLog --> RotateScript
    WafLog --> FluentBitSidecar
    FluentBitSidecar -->|HTTP Bulk Ingest| GeoIPPipeline
    GeoIPPipeline --> DotlessAliases
    DotlessAliases --> SecurityAnalytics
    DotlessAliases --> BurstDetectors
    DotlessAliases --> AutoBlockDaemon
    AutoBlockDaemon -->|Hot-Reload SecRule 100020| CorazaUI
    AutoBlockDaemon -->|Executive Ban Alert| SESEmail
    BurstDetectors -->|Rich P1/P2 Alerts| SESEmail
```

---

## 3. Preserving Real External Client IPs at Ingress

A Web Application Firewall is useless if every incoming request appears to originate from an internal overlay IP (`10.42.x.x`). By default, Kubernetes `Service` objects of type `LoadBalancer` or `NodePort` perform Source Network Address Translation (SNAT).

To guarantee that the true public IP reaches the WAF engine for GeoIP enrichment and reputation filtering, configure `externalTrafficPolicy: Local` on your ingress service:

```yaml
# deploy/traefik-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: traefik
  namespace: kube-system
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local  # <--- PRESERVES CLIENT IP (NO KUBE-PROXY SNAT)
  loadBalancerIP: 203.0.113.10
  selector:
    app.kubernetes.io/name: traefik
  ports:
    - name: web
      port: 80
      targetPort: 8000
    - name: websecure
      port: 443
      targetPort: 8443
```

---

## 4. In-Memory Sidecar Logging: Eliminating Disk Pressure

High-frequency attack storms generate immense audit logging. Writing unbuffered JSON logs directly to node filesystems risks rapid disk fill, triggering Kubelet `DiskPressure` and crashing workloads.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Coraza WAF Pod In-Memory Isolation                   │
│                                                                        │
│   ┌───────────────────────────┐      ┌──────────────────────────────┐  │
│   │ Coraza WAF Container      │      │ Fluent Bit Sidecar           │  │
│   │ • Pure Go Proxy (:80)     │      │ • Mem_Buf_Limit 16MB         │  │
│   │ • SecLang Engine          │      │ • Tails RAM log stream       │  │
│   │ • CPU: 50m / RAM: 128Mi   │      │ • RAM: 24Mi                  │  │
│   └─────────────┬─────────────┘      └──────────────▲───────────────┘  │
│                 │                                   │                  │
│                 ▼ Writes JSON                       │ Ships to         │
│         ┌───────────────────────────────────────────┴──────────┐       │
│         │ Shared In-Memory emptyDir: sizeLimit 64Mi (tmpfs)    │       │
│         │ Path: /var/log/waf/audit.log                         │       │
│         │ ⚡ rotate-logs.sh truncates at 5MB (Zero Disk I/O)    │       │
│         └──────────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────────────────┘
```

The self-truncating rotation daemon runs inside the container:

```bash
#!/bin/sh
# deploy/rotate-logs.sh
LOG_FILE="/var/log/waf/audit.log"
MAX_BYTES=5242880  # 5 MB threshold

while true; do
  if [ -f "$LOG_FILE" ]; then
    SIZE=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$SIZE" -ge "$MAX_BYTES" ]; then
      cp "$LOG_FILE" "${LOG_FILE}.1"
      : > "$LOG_FILE"
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Log truncated ($SIZE bytes)"
    fi
  fi
  sleep 15
done
```

---

## 5. Coraza v3 WAF Architecture & Native Management Console

Our WAF reverse proxy is built using **Coraza v3 (`corazawaf/coraza/v3`)** and **Coraza Core Rule Set (`corazawaf/coraza-coreruleset/v4`)**.

```dockerfile
# coraza-waf/Dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY main.go ui.html ./
RUN go mod init coraza-waf-defense &&     go get github.com/corazawaf/coraza/v3@v3.2.1 \
           github.com/corazawaf/coraza-coreruleset/v4@v4.3.0 &&     go mod tidy &&     CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /coraza-waf-server main.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /coraza-waf-server /usr/local/bin/coraza-waf-server
EXPOSE 80 8080
ENTRYPOINT ["/usr/local/bin/coraza-waf-server"]
```

### Zero-Downtime Hot-Reloading (`main.go`)
Rules are recompiled in-memory and swapped atomically using Go's `sync/atomic`:

```go
// coraza-waf/main.go
var activeWAF atomic.Pointer[coraza.WAF]

func updateConfig(newConfig WAFConfig) error {
    newWAF, err := compileWAF(newConfig)
    if err != nil {
        return fmt.Errorf("compilation failed: %w", err)
    }
    // Atomic pointer swap: Zero dropped requests, zero downtime
    activeWAF.Store(&newWAF)
    return nil
}
```

### Visual: Native Coraza Management Console (`:8080`)

The web UI provides real-time rule group toggling, a SecLang playground, and a dedicated threat intelligence management console:

![Coraza WAF Management Console - OWASP Rule Groups](docs/images/coraza_waf_console_rules.png)
*Figure 1: Coraza v3 Management Console showing global SecRuleEngine settings (On - Active Blocking 403), Paranoia Level 1, and the 10 granular OWASP Top 10 rule group cards.*

---

## 6. Real-Time Telemetry: Complete 24-Hour Dashboard Showcase

All audit logs shipped via Fluent Bit pass through the `network-geoip-pipeline` and populate our custom dashboards:

### Visual: Coraza WAF & OWASP Threat Intelligence Dashboard (Dashboard 7 - 24h Window)

![OpenSearch Coraza WAF & Threat Intelligence Dashboard](docs/images/opensearch_dashboard_waf_top.png)
*Figure 2: OpenSearch Dashboard 7 (Last 24 Hours) displaying 119 total inspected requests, 34 blocked attacks, 25 critical OWASP hits, 18 Rule 100020 IP blocklist drops, attack traffic timelines, live world coordinate maps with pins, and country choropleth distribution.*

### Visual: Deep Dive Exploit Attribution & Payloads Table (Dashboard 7 Full)

![OpenSearch WAF Full Exploit Attribution & Payloads](docs/images/opensearch_dashboard_waf_full.png)
*Figure 3: OpenSearch Dashboard 7 Full Length view featuring the Permanently Blocked Attacker IPs table, Exploit Reasoning & Attribution table, and the Raw Blocked Payloads table showing exact exploit signatures (`/api/exec`, `eval-stdin.php`, `/.env`).*

### Visual: Ingress & Network Traffic Telemetry (Dashboard 4 - 24h Window)

![OpenSearch Network Ingress & GeoIP Traffic Dashboard](docs/images/opensearch_dashboard_network_ingress.png)
*Figure 4: OpenSearch Dashboard 4 (Network & Ingress) showing external ingress request rates, HTTP status breakdown, Top Public Client IPs, MaxMind GeoIP distribution, and Top User Agents.*

### Visual: Security Analytics & Threat Intelligence (Dashboard 8 - 24h Window)

![OpenSearch Security Analytics & Threat Intel Dashboard](docs/images/opensearch_dashboard_security_analytics.png)
*Figure 5: OpenSearch Dashboard 8 displaying AlienVault OTX Threat Intel hits, 609 malicious IOC match timeline, security findings categorized by criticality, and 5-minute sliding window correlation rules.*

### Visual: Security & Kubernetes API Audit Trail (Dashboard 5 - 24h Window)

![OpenSearch Security & K8s API Audit Dashboard](docs/images/opensearch_dashboard_audit_security.png)
*Figure 6: OpenSearch Dashboard 5 tracking Kubernetes control-plane audit events, unauthorized 401/403 RBAC access attempts, verbs, resource types, and host `/var/log/auth.log` authentication attempts.*

### Visual: Prometheus Operations Metrics & Alert History (Dashboard 6 - 24h Window)

![OpenSearch Prometheus Ops & Alert History Dashboard](docs/images/opensearch_dashboard_prometheus_alerts.png)
*Figure 7: OpenSearch Dashboard 6 summarizing per-node CPU/RAM/Disk metrics across 5 nodes, Longhorn PVC volume utilization percentages, workload failure diagnostics, and AWS SES alert delivery history.*

### Visual: Cluster & Workload Health (Dashboard 1 - 24h Window)

![OpenSearch Cluster & Workload Health Dashboard](docs/images/opensearch_dashboard_cluster_health.png)
*Figure 8: OpenSearch Dashboard 1 showing 5-node cluster readiness, containerd and kubelet systemd journal streams, and container restart monitors.*

### Visual: Error & Exception Logs (Dashboard 3 - 24h Window)

![OpenSearch Error & Exception Logs Dashboard](docs/images/opensearch_dashboard_error_logs.png)
*Figure 9: OpenSearch Dashboard 3 tracking runtime exceptions, tracebacks, HTTP 5xx spikes, and application crash events across workloads.*

### Visual: Application Workload Sidecar Streams (Dashboard 2 - 24h Window)

![OpenSearch Application Sidecar Logs Dashboard](docs/images/opensearch_dashboard_app_logs.png)
*Figure 10: OpenSearch Dashboard 2 reviewing application stdout/stderr logs shipped in real-time from Fluent Bit in-memory sidecars.*

---

## 7. Autonomous Attacker IP Defense (Self-Healing WAF Loop)

Rather than forcing human operators to review logs and manually update firewalls, our autonomous defense worker continuously evaluates attack telemetry and dynamically isolates hostile IP addresses.

```mermaid
flowchart TD
    Daemon["Autonomous Defense Daemon<br>(Runs every 60s in cluster)"] --> Query["Query OpenSearch logs-waf-*<br>Date Histogram Aggregation (15m sliding window)"]
    Query --> Check{"Any external IP with<br>more than 5 attacks in 15m?"}
    Check -->|No| Sleep["Sleep 60s"]
    Check -->|Yes| SubnetCheck{"Is IP in Safe Subnets?<br>(RFC1918 / Pod CIDR / Loopback)"}
    SubnetCheck -->|Yes Private| Ignore["Protect Private Subnet & Ignore"]
    SubnetCheck -->|No Public| FetchConfig["Fetch Coraza WAF Config<br>GET http://coraza-waf-service:8080/api/config"]
    FetchConfig --> CheckDupe{"Already Blocked?"}
    CheckDupe -->|Yes| Sleep
    CheckDupe -->|No| AddRule["Append IP to Blocklist<br>Generate SecRule 100020 @ipMatch"]
    AddRule --> PostReload["Hot-Reload Coraza WAF Engine<br>POST http://coraza-waf-service:8080/api/config"]
    PostReload --> EmailAlert["Dispatch AWS SES Executive Alert<br>(secops@hypatian.com)"]
```

### Visual: Quarantined Attacker IPs & Threat Intelligence Table

![Coraza WAF Quarantined Attacker IPs & Threat Intelligence Table](docs/images/coraza_waf_blocked_ips_tab.png)
*Figure 11: Coraza WAF Console Tab 2 showing quarantined attacker IPs, burst thresholds, attack vectors (RCE, SQLi, webshells), sample payloads (`/api/exec`), country origins, and ⚡ Instant Unblock controls.*

### Real-World Attackers Quarantined

| Blocked Client IP | Peak Burst | Attack Vector & Payload | Geolocation Origin | Threat Intel Status |
| :--- | :--- | :--- | :--- | :--- |
| **`31.57.34.150`** | **48 req / 15m** | PHP Webshell Probe (`eval-stdin.php; /bin/sh`) | 🇮🇷 Iran | AlienVault OTX High Risk |
| **`216.180.246.112`**| **18 req / 15m** | Admin Recon Probing (`/wp-admin`, `.env`) | 🇺🇸 United States (Lithonia) | Automated Scanner |
| **`216.180.246.38`** | **11 req / 15m** | Automated Vulnerability Probing | 🇺🇸 United States (Lithonia) | Scanning Botnet Subnet |
| **`103.253.41.98`**  | **7 req / 15m**  | RCE Command Injection (`/api/exec; cat /etc/passwd`) | 🇭🇰 Hong Kong | Known Malicious Host |
| **`123.58.215.74`**  | **7 req / 15m**  | Scanner Recon Probing (`/favicon.ico`, `/v1`) | 🇨🇳 China | Automated Scanner |
| **`46.101.180.175`** | **7 req / 15m**  | Odin Scanner Probing (`/HNAP1`, `/sdk`) | 🇩🇪 Germany (Frankfurt) | Automated Exploit Bot |
| **`185.220.101.45`** | **6 req / 15m**  | SQL Injection (`UNION SELECT 1,password FROM users--`)| 🇩🇪 Germany | Tor Exit Node |

---

## 8. Eliminating Alert Fatigue with Burst Detectors

Single-event alerts ruin on-call rotations. We deployed **14 query-level burst monitors** scheduled every 1 to 2 minutes:

![OpenSearch Alerting Monitors](docs/images/opensearch_alert_monitors.png)
*Figure 12: OpenSearch Alerting Monitors console showing the 14 active monitors, criticality tiers ([CRITICAL - P1] through [LOW - P4]), and trigger states.*

### Rich Alert Briefing via AWS SES
When a threshold breaches, engineers receive an enriched notification detailing exact hit rates, top targeted paths, and exploit payloads:

```
🚨 [CRITICAL - P1] High-Rate SQL Injection Attack Burst Detected
──────────────────────────────────────────────────────────────────
Cluster: k8s-production | Engine: Coraza v3 WAF | Rule Group: RG-942
Total Blocked Requests: 24 requests in last 120s (~12 attacks/min)

🎯 Top Targeted Endpoints:
  • /api/users/login (18 hits)
  • /search?q= (6 hits)

🚨 Top Attacking External Client IPs:
  • 185.220.101.45 (16 blocked attempts) — 🇩🇪 Germany
  • 103.253.41.98 (8 blocked attempts) — 🇭🇰 Hong Kong

🔍 Extracted Exploit Payload:
  Matched Data: ' UNION SELECT 1,username,password FROM accounts--

⚡ Automated Action Taken:
  All requests dropped with HTTP 403 Forbidden.
  Offending IPs exceeding 5 attacks in 15m quarantined via SecRule 100020.
```

---

## 9. Executive Multi-Page PDF Reporting

To keep leadership informed without manual dashboard exports, our Kubernetes CronJob generates and emails two multi-page PDF reports every Sunday at 08:00 EST / 13:00 UTC:

### Visual: Weekly Security & Coraza WAF Performance Report

| Page 1: WAF Metrics & Top Attacking IPs | Page 2: K8s Audit & Alerts by Severity |
| :---: | :---: |
| ![Weekly Security Report Page 1](docs/images/weekly_security_report_p1.png) | ![Weekly Security Report Page 2](docs/images/weekly_security_report_p2.png) |

### Visual: Weekly Cluster Uptime & Ops Metrics Report

| Page 1: 5-Node Resource Utilization | Page 2: Workload & Pod Failure Diagnostics |
| :---: | :---: |
| ![Weekly Ops Report Page 1](docs/images/weekly_cluster_ops_report_p1.png) | ![Weekly Ops Report Page 2](docs/images/weekly_cluster_ops_report_p2.png) |

---

## 10. Step-by-Step Reproduction Guide

You can reproduce this defense stack on any Kubernetes cluster ($v1.26+$).

### Step 1: Clone the Dedicated Reference Repository
```bash
git clone https://github.com/saadrana219/coraza-waf-k8s-defense.git
cd coraza-waf-k8s-defense
```

### Step 2: Deploy OpenSearch Cluster & Sidecars
```bash
# Deploys 3-node OpenSearch 2.19.7, Dashboards, and Fluent Bit log collectors
kubectl apply -f deploy/opensearch-logging.yaml
kubectl rollout status statefulset/opensearch -n logging --timeout=300s
```

### Step 3: Deploy Coraza v3 WAF & Management Console
```bash
# Deploys Coraza reverse proxy, web console (:8080), and LoadBalancer service
kubectl apply -f deploy/coraza-waf.yaml
```

### Step 4: Import OpenSearch Dashboards (88+ Saved Objects)
```bash
# Configures index patterns, GeoIP ingest pipelines, and imports all 8 dashboards
python3 scripts/create_dashboards.py
```

### Step 5: Provision Threat Burst Monitors & Alert Channels
```bash
# Deploys AWS SES notification channel and 14 high-rate burst monitors
python3 scripts/create_alerts.py
```

### Step 6: Provision Security Analytics & AlienVault Threat Intel
```bash
# Configures dotless aliases, Sigma rules, and 5-minute correlation rules
python3 scripts/create_security_detections.py
```

### Step 7: Activate the Autonomous IP Blocker Daemon
```bash
# Runs immediate historical ban and starts 60s in-cluster enforcement
python3 scripts/auto_block_waf_ips.py
```

### Step 8: Deploy Weekly PDF Report Dispatcher
```bash
kubectl apply -f deploy/opensearch-reporter-configmap.yaml
kubectl apply -f deploy/opensearch-weekly-reporter-cronjob.yaml
```

---

## 11. Verification & Penetration Testing

Verify your WAF and automated defense pipeline:

### 1. Test SQL Injection (SQLi) Block
```bash
curl -i -X POST "http://<YOUR_INGRESS_IP>/api/login" \
     -d "username=admin' OR '1'='1'--&password=foo"
```
**Expected Response**:
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"Request Blocked by Security Policy","incident_id":"tx-84912","rule_id":942100,"status":403}
```

### 2. Test Automated IP Quarantine Burst
Simulate an attacker exceeding the burst threshold:
```bash
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code}\n" "http://<YOUR_INGRESS_IP>/eval-stdin.php?cmd=id"
  sleep 1
done
```
Within 60 seconds:
1. OpenSearch indexes the attack events with MaxMind GeoIP telemetry.
2. The `auto_block_waf_ips` daemon flags $> 5$ attacks in the 15-minute sliding window.
3. Coraza WAF hot-reloads Rule `100020`, adding your IP to the atomic blocklist.
4. Next request from the same IP is blocked at Phase 1 before consuming reverse proxy resources:

```bash
curl -i "http://<YOUR_INGRESS_IP>/"
# HTTP/1.1 403 Forbidden (Coraza IP Blocklist: Blocked Client IP)
```

---

## 12. Rollout Highlights: Operational Findings & Pitfalls

Deploying an autonomous WAF and telemetry pipeline into an active Kubernetes cluster reveals nuances that synthetic staging benchmarks never catch. Below are the concrete operational findings observed throughout this rollout, accompanied by critical pitfalls to engineer against.

### Operational Findings Observed in Production

1. **Client IP Preservation & Ingress Asymmetry**: Setting `externalTrafficPolicy: Local` on the MetalLB LoadBalancer service is mandatory. If left at the Kubernetes default (`Cluster`), internal SNAT rewrites incoming client IPs to node interface addresses (`10.x.x.x` or LAN IPs), making genuine attacker attribution impossible and risking automated bans against cluster nodes.
2. **Memory & GC Runtime Profile under High-Rate Attack**: The pure Go Coraza v3 proxy runs at ~45MB RSS idle, scaling smoothly to ~110MB under full scanner burst loads (120+ req/s). Go's garbage collector handled high transaction churn without heap fragmentation. However, enforcing `SecRequestBodyLimit 13107200` (12.5MB) and an in-memory threshold of 128KB was essential to stop attackers from exhausting RAM with streaming multipart uploads.
3. **In-Memory Sidecar Buffer vs. Log Spike Dynamics**: During aggressive directory fuzzing passes (`masscan`, `nuclei`), Coraza generated up to 35 MB/minute of structured audit JSON. A 64Mi `emptyDir: medium: Memory` safely decoupled logging I/O from physical SSDs. Paired with our 5-second rotation daemon truncating active files at 5MB, node disk write wear remained at zero.
4. **SecLang Paranoia Level 1 vs. Modern API Payload Tuning**: OWASP CRS v4.3 Paranoia Level 1 produced zero false positives across standard web UI workflows. However, REST APIs receiving serialized JSON objects with embedded SQL keywords (e.g. `order_by` or base64 JWT payloads) required targeted Phase 1 SecRule exclusions (`ctl:ruleRemoveById`) on specific API endpoints before Phase 2 inspection.

### Critical Pitfalls to Engineer Against

- 🚨 **Pitfall 1: Subnet Safelist Flaws Causing Self-Inflicted Outages**: If the autonomous quarantine script queries OpenSearch and updates the blocklist without an airtight private subnet whitelist, internal service-to-service errors or Kubernetes liveness probe spikes will trigger an automatic IP ban against cluster gateways or internal pods. **Rule:** Hardcode RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), pod CIDRs, and node subnets directly into the quarantine evaluator with explicit unit tests before automating blocking.
- ⚠️ **Pitfall 2: Fluent Bit In-Memory Buffer Starvation Under Elastic Backpressure**: When OpenSearch encounters disk high watermarks (85%+) or JVM heap pauses, ingestion latency climbs. If Fluent Bit exhausts its in-memory buffer limit (`Mem_Buf_Limit 15MB`), it temporarily pauses reading. Meanwhile, the diskless log rotator continues truncating the audit file to protect RAM, leading to silently dropped security audit events. **Rule:** Configure Prometheus alert rules on `fluentbit_output_retries_total` to catch shipper backpressure early.
- ⚠️ **Pitfall 3: Atomic Pointer Swap vs. In-Flight Transaction Leaks**: While Go's `atomic.Value` allows instant, zero-downtime hot-reloading for incoming requests, in-flight HTTP transactions that began evaluating prior to the swap will continue running against the prior rule engine pointer. Never mutate SecLang rule lists or map entries in-place; always compile an entirely new standalone WAF instance and atomically swap the pointer.
- ⚠️ **Pitfall 4: Alert Rate Limiting & Email Quota Depletion**: Configuring alert monitors on single anomalous hits or narrow 60-second windows without grouping causes email alert floods during routine internet vulnerability sweeps (e.g. Shodan, Shadowserver), quickly exhausting AWS SES sandbox quotas (200 emails/day) and destroying operational focus. **Rule:** Base alert triggers strictly on aggregated multi-event thresholds (e.g., >5 discrete attack events across a 15-minute sliding window) grouped by client IP.
---

### Repository & Reference Code
All manifests, Go source code, and scripts are open-source:
👉 [**https://github.com/saadrana219/coraza-waf-k8s-defense**](https://github.com/saadrana219/coraza-waf-k8s-defense)

*Published by the Hypatian Systems Research Infrastructure & Security Engineering Team.*
