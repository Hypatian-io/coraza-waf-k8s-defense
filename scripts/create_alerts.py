#!/usr/bin/env python3
"""
Provision OpenSearch Alerting Monitors & AWS SES Notification Channel
for the Hypatian Kubernetes Homelab Cluster.

All monitors dispatch structured alerts via OpenSearch Notifications
to `prometheus-opensearch-bridge` (http://prometheus-opensearch-bridge.logging.svc.cluster.local:8080/webhook),
which sends formatted emails via AWS SES (us-east-1) from:
  alert@hypatian.io -> saad@hypatian.io
with consistent criticality tags:
  - Sev 1: [CRITICAL - P1]
  - Sev 2: [HIGH - P2]
  - Sev 3: [MEDIUM - P3]
  - Sev 4: [LOW - P4]
"""
import json
import subprocess
import sys

CHANNEL_ID = "hypatian-ses-email-channel"
WEBHOOK_URL = "http://prometheus-opensearch-bridge.logging.svc.cluster.local:8080/webhook"


def os_request(method, path, body=None):
    cmd = [
        "kubectl", "exec", "-n", "logging", "opensearch-0", "--",
        "curl", "-s", "-X", method, f"http://localhost:9200{path}",
        "-H", "Content-Type: application/json"
    ]
    if body is not None:
        cmd.extend(["-d", json.dumps(body)])
    out = subprocess.check_output(cmd).decode("utf-8")
    try:
        return json.loads(out)
    except Exception:
        return {"raw": out}


def configure_alerting_settings():
    settings = {
        "persistent": {
            "plugins.alerting.alert_history_retention_period": "7d",
            "plugins.alerting.alert_history_max_age": "7d",
            "plugins.alerting.finding_history_retention_period": "7d",
            "plugins.alerting.finding_history_max_age": "7d",
            "plugins.alerting.comments_history_retention_period": "7d",
            "plugins.alerting.comments_history_max_age": "7d",
        }
    }
    res = os_request("PUT", "/_cluster/settings", settings)
    print(f"[settings] Configured 7-day OpenSearch Alerting history retention: {res.get('acknowledged')}")


def ensure_notification_channel():
    channel_payload = {
        "config": {
            "name": "Hypatian AWS SES Alert Email Relay (alert@hypatian.io -> saad@hypatian.io)",
            "description": "Sends OpenSearch alerts with consistent criticality ([CRITICAL - P1] through [LOW - P4]) from alert@hypatian.io to saad@hypatian.io via AWS SES",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": WEBHOOK_URL,
                "header_params": {"Content-Type": "application/json"},
                "method": "POST"
            }
        }
    }
    existing = os_request("GET", f"/_plugins/_notifications/configs/{CHANNEL_ID}")
    if "config_list" in existing or "config" in existing:
        res = os_request("PUT", f"/_plugins/_notifications/configs/{CHANNEL_ID}", channel_payload)
        print(f"[channel] Updated notification channel '{CHANNEL_ID}': {res}")
    else:
        create_payload = {"config_id": CHANNEL_ID, **channel_payload}
        res = os_request("POST", "/_plugins/_notifications/configs/", create_payload)
        print(f"[channel] Created notification channel '{CHANNEL_ID}': {res}")


def make_query_monitor(name, interval_mins, indices, query_dsl, trigger_name, severity, condition_script, category, summary_template, throttle_mins=30, details_template=None):
    details_str = details_template or "Monitor: {{ctx.monitor.name}} | Trigger: {{ctx.trigger.name}} | Severity: {{ctx.trigger.severity}} | Window: {{ctx.periodStart}} to {{ctx.periodEnd}} | Total Matching Docs: {{ctx.results.0.hits.total.value}}"
    msg_payload = {
        "monitor_name": name,
        "trigger_name": trigger_name,
        "severity": str(severity),
        "category": category,
        "summary": summary_template,
        "details": details_str
    }
    return {
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "name": name,
        "enabled": True,
        "schedule": {
            "period": {
                "interval": interval_mins,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "search": {
                    "indices": indices,
                    "query": query_dsl
                }
            }
        ],
        "triggers": [
            {
                "query_level_trigger": {
                    "name": trigger_name,
                    "severity": str(severity),
                    "condition": {
                        "script": {
                            "source": condition_script,
                            "lang": "painless"
                        }
                    },
                    "actions": [
                        {
                            "name": f"Email saad@hypatian.io from alert@hypatian.io (Sev {severity})",
                            "destination_id": CHANNEL_ID,
                            "subject_template": {
                                "source": f"[Sev {severity}] Hypatian K8s Alert: {name}",
                                "lang": "mustache"
                            },
                            "message_template": {
                                "source": json.dumps(msg_payload),
                                "lang": "mustache"
                            },
                            "throttle_enabled": True,
                            "throttle": {
                                "value": throttle_mins,
                                "unit": "MINUTES"
                            }
                        }
                    ]
                }
            }
        ]
    }


def build_monitors():
    monitors = []

    # 1. [CRITICAL - Sev 1] Cluster Outage & Node Availability Monitor
    monitors.append(make_query_monitor(
        name="1. [CRITICAL] Cluster Outage & Node Availability Monitor",
        interval_mins=1,
        indices=["metrics-cluster-*"],
        query_dsl={
            "size": 1,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"metric_type.keyword": "cluster_summary"}},
                        {"range": {"@timestamp": {"gte": "now-3m", "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "max_not_ready": {"max": {"field": "nodes_not_ready"}},
                "min_ready": {"min": {"field": "nodes_ready"}},
                "max_os_code": {"max": {"field": "opensearch_status_code"}}
            }
        },
        trigger_name="Kubernetes Node NotReady or OpenSearch Cluster Red",
        severity="1",
        condition_script=(
            "ctx.results[0].hits.total.value == 0 || "
            "(ctx.results[0].aggregations.max_not_ready.value != null && ctx.results[0].aggregations.max_not_ready.value > 0) || "
            "(ctx.results[0].aggregations.min_ready.value != null && ctx.results[0].aggregations.min_ready.value < 5) || "
            "(ctx.results[0].aggregations.max_os_code.value != null && ctx.results[0].aggregations.max_os_code.value >= 2)"
        ),
        category="Cluster Health & Outage (Prometheus + OpenSearch)",
        summary_template="One or more Kubernetes nodes reported NotReady (expected 5/5 Ready nodes: kubeapi, kubeworker1..4), metrics heartbeat was lost, or OpenSearch cluster health entered RED state."
    ))

    # 2. [CRITICAL - Sev 1] Control-Plane & Storage Outage Log Monitor
    monitors.append(make_query_monitor(
        name="2. [CRITICAL] Control-Plane & Storage Outage Log Monitor",
        interval_mins=2,
        indices=["logs-cluster-*"],
        query_dsl={
            "size": 5,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {"match_phrase": {"log": "etcdserver: request timed out"}},
                        {"match_phrase": {"log": "leader lost"}},
                        {"match_phrase": {"log": "PLEG is not healthy"}},
                        {"match_phrase": {"log": "NodeNotReady"}},
                        {"match_phrase": {"log": "FailedAttachVolume"}},
                        {"match_phrase": {"MESSAGE": "PLEG is not healthy"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Control-Plane / Etcd / Longhorn Storage Outage Detected",
        severity="1",
        condition_script="ctx.results[0].hits.total.value >= 3",
        category="Control-Plane & Storage Reliability",
        summary_template="Detected {{ctx.results.0.hits.total.value}} critical control-plane or storage outage events (etcd timeout, kubelet PLEG unhealthy, NodeNotReady, or Longhorn FailedAttachVolume) in the last 5 minutes."
    ))

    # 3. [HIGH - Sev 2] Pod Failure, CrashLoopBackOff & OOMKilled Monitor
    monitors.append(make_query_monitor(
        name="3. [HIGH] Pod Failure, CrashLoopBackOff & OOMKilled Monitor",
        interval_mins=2,
        indices=["metrics-cluster-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"metric_type.keyword": "pod_metrics"}},
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {"term": {"is_failing": 1}},
                        {"range": {"restarts_15m": {"gte": 3}}}
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Pod CrashLoopBackOff, ImagePullBackOff, OOMKilled, or >=3 Restarts/15m",
        severity="2",
        condition_script="ctx.results[0].hits.total.value > 0",
        category="Workload & Pod Health (Prometheus kube-state-metrics)",
        summary_template="Detected failing pod in cluster: Pod '{{ctx.results.0.hits.hits.0._source.namespace}}/{{ctx.results.0.hits.hits.0._source.pod}}' on Worker Node '{{ctx.results.0.hits.hits.0._source.node}}' (Host IP: {{ctx.results.0.hits.hits.0._source.host_ip}}) | Container: {{ctx.results.0.hits.hits.0._source.container}} | Root Cause: {{ctx.results.0.hits.hits.0._source.failure_cause}}",
        details_template="Pod Name: {{ctx.results.0.hits.hits.0._source.namespace}}/{{ctx.results.0.hits.hits.0._source.pod}}\nWorker Node: {{ctx.results.0.hits.hits.0._source.node}} (Host IP: {{ctx.results.0.hits.hits.0._source.host_ip}})\nContainer: {{ctx.results.0.hits.hits.0._source.container}}\nWaiting Reason: {{ctx.results.0.hits.hits.0._source.waiting_reason}}\nTerminated Reason: {{ctx.results.0.hits.hits.0._source.terminated_reason}}\nExit Code: {{ctx.results.0.hits.hits.0._source.exit_code}}\nRestarts in 15m: {{ctx.results.0.hits.hits.0._source.restarts_15m}}\nDetailed Root-Cause Diagnosis:\n{{ctx.results.0.hits.hits.0._source.failure_cause}}"
    ))

    # 4. [HIGH - Sev 2] External IP Rate-Limit Abuse / DDoS Monitor (>=100 req / 5m)
    monitors.append(make_query_monitor(
        name="4. [HIGH] External IP Rate-Limit Abuse Monitor (>=100 req/5m)",
        interval_mins=2,
        indices=["logs-network-*"],
        query_dsl={
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}},
                        {"exists": {"field": "client_ip"}}
                    ],
                    "must_not": [
                        {"prefix": {"client_ip.keyword": "10.244."}},
                        {"term": {"client_ip.keyword": "127.0.0.1"}}
                    ]
                }
            },
            "aggs": {
                "abusive_ips": {
                    "terms": {
                        "field": "client_ip.keyword",
                        "size": 10,
                        "min_doc_count": 100
                    }
                }
            }
        },
        trigger_name="Single External IP Exceeded 100 Requests in 5 Minutes",
        severity="2",
        condition_script="ctx.results[0].aggregations.abusive_ips.buckets.size() > 0",
        category="Network Security & Rate-Limit Protection",
        summary_template="One or more external client IPs exceeded the rate limit of 100 requests within 5 minutes against publicly exposed Hypatian applications (top IP: {{ctx.results.0.aggregations.abusive_ips.buckets.0.key}} with {{ctx.results.0.aggregations.abusive_ips.buckets.0.doc_count}} requests)."
    ))

    # 5. [HIGH - Sev 2] Cluster Node Memory Shortage Monitor (>85% RAM)
    monitors.append(make_query_monitor(
        name="5. [HIGH] Cluster Node Memory Shortage Monitor (>85% RAM)",
        interval_mins=2,
        indices=["metrics-cluster-*"],
        query_dsl={
            "size": 5,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"metric_type.keyword": "node_metrics"}},
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {"range": {"memory_usage_pct": {"gte": 85.0}}},
                        {"range": {"memory_pressure": {"gte": 1}}}
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Node Memory Usage >= 85% or Kubelet MemoryPressure Active",
        severity="2",
        condition_script="ctx.results[0].hits.total.value > 0",
        category="Cluster Resource Capacity (Prometheus node-exporter)",
        summary_template="High memory utilization (>=85%) or Kubelet MemoryPressure detected on cluster node (sample count: {{ctx.results.0.hits.total.value}}, node: {{ctx.results.0.hits.hits.0._source.node}}, memory used: {{ctx.results.0.hits.hits.0._source.memory_usage_pct}}%)."
    ))

    # 6. [HIGH - Sev 2] Node & Longhorn PVC Disk Pressure Monitor (>80% Disk)
    monitors.append(make_query_monitor(
        name="6. [HIGH] Node & Longhorn PVC Disk Pressure Monitor (>80% Disk)",
        interval_mins=5,
        indices=["metrics-cluster-*"],
        query_dsl={
            "size": 5,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {
                            "bool": {
                                "filter": [
                                    {"term": {"metric_type.keyword": "node_metrics"}},
                                    {"range": {"disk_usage_pct": {"gte": 80.0}}}
                                ]
                            }
                        },
                        {
                            "bool": {
                                "filter": [
                                    {"term": {"metric_type.keyword": "node_metrics"}},
                                    {"range": {"disk_pressure": {"gte": 1}}}
                                ]
                            }
                        },
                        {
                            "bool": {
                                "filter": [
                                    {"term": {"metric_type.keyword": "pvc_metrics"}},
                                    {"range": {"volume_usage_pct": {"gte": 80.0}}}
                                ]
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Node Root Filesystem or Longhorn PVC >= 80% Full",
        severity="2",
        condition_script="ctx.results[0].hits.total.value > 0",
        category="Storage & Disk Pressure Protection (Prometheus)",
        summary_template="Disk pressure threshold (>=80% utilization or Kubelet DiskPressure condition) exceeded on a cluster node or Longhorn PersistentVolumeClaim ({{ctx.results.0.hits.total.value}} samples matched in last 5m)."
    ))

    # 7. [MEDIUM - Sev 3] Sustained Node CPU Spike Monitor (>85% CPU)
    monitors.append(make_query_monitor(
        name="7. [MEDIUM] Sustained Node CPU Spike Monitor (>85% CPU)",
        interval_mins=2,
        indices=["metrics-cluster-*"],
        query_dsl={
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"metric_type.keyword": "node_metrics"}},
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "by_node": {
                    "terms": {"field": "node.keyword", "size": 10},
                    "aggs": {
                        "avg_cpu": {"avg": {"field": "cpu_usage_pct"}}
                    }
                },
                "max_node_cpu": {
                    "max_bucket": {
                        "buckets_path": "by_node>avg_cpu"
                    }
                }
            }
        },
        trigger_name="Sustained 5-Minute Node CPU Utilization >= 85%",
        severity="3",
        condition_script=(
            "ctx.results[0].aggregations.max_node_cpu.value != null && "
            "ctx.results[0].aggregations.max_node_cpu.value >= 85.0"
        ),
        category="Cluster Compute Performance (Prometheus node-exporter)",
        summary_template="A Kubernetes node sustained >=85% average CPU utilization over the last 5 minutes (peak 5m node average: {{ctx.results.0.aggregations.max_node_cpu.value}}%)."
    ))

    # 8. [MEDIUM - Sev 3] Application Runtime Error & HTTP 5xx Spike Monitor
    monitors.append(make_query_monitor(
        name="8. [MEDIUM] Application Runtime Error & HTTP 5xx Spike Monitor",
        interval_mins=2,
        indices=["logs-error-*"],
        query_dsl={
            "size": 5,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {"term": {"shipper.keyword": "sidecar"}},
                        {"range": {"status": {"gte": 500, "lte": 599}}},
                        {"match_phrase": {"log": "Traceback"}},
                        {"match_phrase": {"log": "Exception"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Application Error or HTTP 5xx Spike (>= 15 errors / 5m)",
        severity="3",
        condition_script="ctx.results[0].hits.total.value >= 15",
        category="Application Sidecar & HTTP Reliability",
        summary_template="Application error or HTTP 5xx spike detected across Hypatian workloads ({{ctx.results.0.hits.total.value}} error events in the last 5 minutes across hypatian-web, hypatian-web-app, azaan-app, homeassistant, or mariadb-galera)."
    ))

    # 9. [LOW - Sev 4] Security & Unauthorized Kubernetes API / SSH Audit Monitor
    monitors.append(make_query_monitor(
        name="9. [LOW] Security & Unauthorized API / SSH Audit Monitor",
        interval_mins=5,
        indices=["logs-audit-*"],
        query_dsl={
            "size": 5,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}}
                    ],
                    "should": [
                        {"terms": {"responseStatus.code": [401, 403]}},
                        {"match_phrase": {"message": "Failed password"}},
                        {"match_phrase": {"message": "Invalid user"}},
                        {"match_phrase": {"message": "authentication failure"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        },
        trigger_name="Unauthorized K8s API (401/403) or SSH Auth Failure Spike (>= 10 / 5m)",
        severity="4",
        condition_script="ctx.results[0].hits.total.value >= 10",
        category="Security & Kubernetes Audit Compliance",
        summary_template="Detected {{ctx.results.0.hits.total.value}} unauthorized Kubernetes API requests (HTTP 401/403) or host SSH authentication failures in logs-audit-* over the last 5 minutes."
    ))

    # 10. [CRITICAL - Sev 1] Coraza WAF SQL Injection Attack Burst Detector (>=5 req/2m)
    sqli_details = (
        "ATTACK CLASS: Injection (SQLi) | OWASP A03:2021 | CRS 942 | @detectSQLi\n"
        "HIT RATE: {{ctx.results.0.hits.total.value}} blocked attacks in last 2 minutes\n"
        "TARGETED HOST: {{ctx.results.0.hits.hits.0._source.host}}\n"
        "PEAK ATTACKED URI: {{ctx.results.0.hits.hits.0._source.request_uri}}\n\n"
        "TOP ATTACKED URL PATHS:{{#ctx.results.0.aggregations.top_paths.buckets}} [{{key}} ({{doc_count}} hits)]{{/ctx.results.0.aggregations.top_paths.buckets}}\n\n"
        "TOP ATTACKING CLIENT IPS:{{#ctx.results.0.aggregations.top_ips.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.top_ips.buckets}}\n\n"
        "RECENT ATTACK SAMPLES:{{#ctx.results.0.hits.hits}} [{{_source.@timestamp}} IP: {{_source.client_ip}} | Method: {{_source.request_method}} | URI: {{_source.request_uri}} | Rule: {{_source.rule_id}} ({{_source.rule_msg}}) | Matched: {{_source.matched_data}}]{{/ctx.results.0.hits.hits}}"
    )
    monitors.append(make_query_monitor(
        name="10. [CRITICAL] Coraza WAF SQL Injection Attack Burst Detector (>=5 req/2m)",
        interval_mins=1,
        indices=["logs-waf-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-2m", "lte": "now"}}},
                        {"term": {"action.keyword": "blocked"}}
                    ],
                    "should": [
                        {"term": {"owasp_category.keyword": "Injection (SQLi)"}},
                        {"wildcard": {"rule_msg.keyword": "*SQL*"}},
                        {"range": {"rule_id": {"gte": 942000, "lte": 942999}}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "top_paths": {"terms": {"field": "request_uri.keyword", "size": 5}},
                "top_ips": {"terms": {"field": "client_ip.keyword", "size": 5}}
            }
        },
        trigger_name="High Rate SQL Injection Attacks (>= 5 Blocked in 2 Minutes)",
        severity="1",
        condition_script="ctx.results[0].hits.total.value >= 5",
        category="Coraza WAF & OWASP Threat Protection (SQLi)",
        summary_template="High rate of SQL Injection attacks detected and blocked by Coraza WAF! (Hit Rate: {{ctx.results.0.hits.total.value}} attacks in 2m | Peak Path: {{ctx.results.0.hits.hits.0._source.request_uri}} | Host: {{ctx.results.0.hits.hits.0._source.host}})",
        throttle_mins=15,
        details_template=sqli_details
    ))

    # 11. [CRITICAL - Sev 1] Coraza WAF Remote Code Execution & LFI Burst Detector (>=3 req/2m)
    rce_details = (
        "ATTACK CLASS: Remote Code Execution (RCE) & Path Traversal (LFI) | OWASP A03/A01 | CRS 930/932/944\n"
        "HIT RATE: {{ctx.results.0.hits.total.value}} blocked attacks in last 2 minutes\n"
        "TARGETED HOST: {{ctx.results.0.hits.hits.0._source.host}}\n"
        "PEAK ATTACKED URI: {{ctx.results.0.hits.hits.0._source.request_uri}}\n\n"
        "TOP ATTACKED URL PATHS:{{#ctx.results.0.aggregations.top_paths.buckets}} [{{key}} ({{doc_count}} hits)]{{/ctx.results.0.aggregations.top_paths.buckets}}\n\n"
        "TOP ATTACKING CLIENT IPS:{{#ctx.results.0.aggregations.top_ips.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.top_ips.buckets}}\n\n"
        "RECENT ATTACK SAMPLES:{{#ctx.results.0.hits.hits}} [{{_source.@timestamp}} IP: {{_source.client_ip}} | Method: {{_source.request_method}} | URI: {{_source.request_uri}} | Rule: {{_source.rule_id}} ({{_source.rule_msg}}) | Matched: {{_source.matched_data}}]{{/ctx.results.0.hits.hits}}"
    )
    monitors.append(make_query_monitor(
        name="11. [CRITICAL] Coraza WAF Remote Code Execution & LFI Burst Detector (>=3 req/2m)",
        interval_mins=1,
        indices=["logs-waf-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-2m", "lte": "now"}}},
                        {"term": {"action.keyword": "blocked"}}
                    ],
                    "should": [
                        {"term": {"owasp_category.keyword": "Remote Code Execution"}},
                        {"term": {"owasp_category.keyword": "Path Traversal / LFI"}},
                        {"term": {"owasp_category.keyword": "Log4Shell / Injection / Deserialization"}},
                        {"range": {"rule_id": {"gte": 930000, "lte": 932999}}},
                        {"range": {"rule_id": {"gte": 944000, "lte": 944999}}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "top_paths": {"terms": {"field": "request_uri.keyword", "size": 5}},
                "top_ips": {"terms": {"field": "client_ip.keyword", "size": 5}}
            }
        },
        trigger_name="High Rate RCE / Command Injection / LFI Attacks (>= 3 Blocked in 2 Minutes)",
        severity="1",
        condition_script="ctx.results[0].hits.total.value >= 3",
        category="Coraza WAF & OWASP Threat Protection (RCE / LFI)",
        summary_template="High rate of Remote Code Execution or LFI attacks detected and blocked by Coraza WAF! (Hit Rate: {{ctx.results.0.hits.total.value}} attacks in 2m | Peak Path: {{ctx.results.0.hits.hits.0._source.request_uri}} | Host: {{ctx.results.0.hits.hits.0._source.host}})",
        throttle_mins=15,
        details_template=rce_details
    ))

    # 12. [HIGH - Sev 2] Coraza WAF Cross-Site Scripting (XSS) Burst Detector (>=5 req/2m)
    xss_details = (
        "ATTACK CLASS: Cross-Site Scripting (XSS) | OWASP A03:2021 | CRS 941 | @detectXSS\n"
        "HIT RATE: {{ctx.results.0.hits.total.value}} blocked attacks in last 2 minutes\n"
        "TARGETED HOST: {{ctx.results.0.hits.hits.0._source.host}}\n"
        "PEAK ATTACKED URI: {{ctx.results.0.hits.hits.0._source.request_uri}}\n\n"
        "TOP ATTACKED URL PATHS:{{#ctx.results.0.aggregations.top_paths.buckets}} [{{key}} ({{doc_count}} hits)]{{/ctx.results.0.aggregations.top_paths.buckets}}\n\n"
        "TOP ATTACKING CLIENT IPS:{{#ctx.results.0.aggregations.top_ips.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.top_ips.buckets}}\n\n"
        "RECENT ATTACK SAMPLES:{{#ctx.results.0.hits.hits}} [{{_source.@timestamp}} IP: {{_source.client_ip}} | Method: {{_source.request_method}} | URI: {{_source.request_uri}} | Rule: {{_source.rule_id}} ({{_source.rule_msg}}) | Matched: {{_source.matched_data}}]{{/ctx.results.0.hits.hits}}"
    )
    monitors.append(make_query_monitor(
        name="12. [HIGH] Coraza WAF Cross-Site Scripting (XSS) Burst Detector (>=5 req/2m)",
        interval_mins=1,
        indices=["logs-waf-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-2m", "lte": "now"}}},
                        {"term": {"action.keyword": "blocked"}}
                    ],
                    "should": [
                        {"term": {"owasp_category.keyword": "Cross-Site Scripting (XSS)"}},
                        {"wildcard": {"rule_msg.keyword": "*XSS*"}},
                        {"range": {"rule_id": {"gte": 941000, "lte": 941999}}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "top_paths": {"terms": {"field": "request_uri.keyword", "size": 5}},
                "top_ips": {"terms": {"field": "client_ip.keyword", "size": 5}}
            }
        },
        trigger_name="High Rate Cross-Site Scripting Attacks (>= 5 Blocked in 2 Minutes)",
        severity="2",
        condition_script="ctx.results[0].hits.total.value >= 5",
        category="Coraza WAF & OWASP Threat Protection (XSS)",
        summary_template="High rate of Cross-Site Scripting (XSS) attacks detected and blocked by Coraza WAF! (Hit Rate: {{ctx.results.0.hits.total.value}} attacks in 2m | Peak Path: {{ctx.results.0.hits.hits.0._source.request_uri}} | Host: {{ctx.results.0.hits.hits.0._source.host}})",
        throttle_mins=15,
        details_template=xss_details
    ))

    # 13. [HIGH - Sev 2] Coraza WAF Vulnerability Scanner & Recon Burst Detector (>=10 req/2m)
    scanner_details = (
        "ATTACK CLASS: Automated Vulnerability Scanner & Malicious Recon Probing | CRS 913/920/950\n"
        "HIT RATE: {{ctx.results.0.hits.total.value}} blocked probes in last 2 minutes\n"
        "TARGETED HOST: {{ctx.results.0.hits.hits.0._source.host}}\n"
        "PEAK ATTACKED URI: {{ctx.results.0.hits.hits.0._source.request_uri}}\n\n"
        "TOP PROBED URL PATHS:{{#ctx.results.0.aggregations.top_paths.buckets}} [{{key}} ({{doc_count}} hits)]{{/ctx.results.0.aggregations.top_paths.buckets}}\n\n"
        "TOP ATTACKING CLIENT IPS:{{#ctx.results.0.aggregations.top_ips.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.top_ips.buckets}}\n\n"
        "RECENT SCANNER SAMPLES:{{#ctx.results.0.hits.hits}} [{{_source.@timestamp}} IP: {{_source.client_ip}} | Method: {{_source.request_method}} | URI: {{_source.request_uri}} | UA: {{_source.user_agent}} | Rule: {{_source.rule_id}} ({{_source.rule_msg}})]{{/ctx.results.0.hits.hits}}"
    )
    monitors.append(make_query_monitor(
        name="13. [HIGH] Coraza WAF Vulnerability Scanner & Recon Burst Detector (>=10 req/2m)",
        interval_mins=1,
        indices=["logs-waf-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-2m", "lte": "now"}}},
                        {"term": {"action.keyword": "blocked"}}
                    ],
                    "should": [
                        {"term": {"owasp_category.keyword": "Scanner Detection"}},
                        {"term": {"owasp_category.keyword": "Known Bad Inputs / Exploit Probe"}},
                        {"term": {"owasp_category.keyword": "Protocol Enforcement"}},
                        {"range": {"rule_id": {"gte": 913000, "lte": 921999}}},
                        {"range": {"rule_id": {"gte": 950000, "lte": 959999}}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "aggs": {
                "top_paths": {"terms": {"field": "request_uri.keyword", "size": 5}},
                "top_ips": {"terms": {"field": "client_ip.keyword", "size": 5}}
            }
        },
        trigger_name="High Rate Vulnerability Scanner & Recon Probing (>= 10 Blocked in 2 Minutes)",
        severity="2",
        condition_script="ctx.results[0].hits.total.value >= 10",
        category="Coraza WAF & Automated Scanner Defense",
        summary_template="High rate of automated vulnerability scanner and exploit probing detected and blocked by Coraza WAF! (Hit Rate: {{ctx.results.0.hits.total.value}} probes in 2m | Peak Path: {{ctx.results.0.hits.hits.0._source.request_uri}} | Host: {{ctx.results.0.hits.hits.0._source.host}})",
        throttle_mins=15,
        details_template=scanner_details
    ))

    # 14. [CRITICAL - Sev 1] Coraza WAF Multi-Class High-Rate Attack Burst Detector (>=15 req/2m)
    burst_details = (
        "ATTACK CLASS: Multi-Class Distributed Attack Burst across All WAF Categories\n"
        "HIT RATE: {{ctx.results.0.hits.total.value}} total blocked attacks in last 2 minutes\n"
        "TARGETED HOST: {{ctx.results.0.hits.hits.0._source.host}}\n"
        "PEAK ATTACKED URI: {{ctx.results.0.hits.hits.0._source.request_uri}}\n\n"
        "ATTACK CATEGORY BREAKDOWN:{{#ctx.results.0.aggregations.by_class.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.by_class.buckets}}\n\n"
        "TOP ATTACKED URL PATHS:{{#ctx.results.0.aggregations.top_paths.buckets}} [{{key}} ({{doc_count}} hits)]{{/ctx.results.0.aggregations.top_paths.buckets}}\n\n"
        "TOP ATTACKING CLIENT IPS:{{#ctx.results.0.aggregations.top_ips.buckets}} [{{key}} ({{doc_count}} attacks)]{{/ctx.results.0.aggregations.top_ips.buckets}}\n\n"
        "RECENT ATTACK SAMPLES:{{#ctx.results.0.hits.hits}} [{{_source.@timestamp}} IP: {{_source.client_ip}} | Method: {{_source.request_method}} | URI: {{_source.request_uri}} | Rule: {{_source.rule_id}} ({{_source.rule_msg}}) | Matched: {{_source.matched_data}}]{{/ctx.results.0.hits.hits}}"
    )
    monitors.append(make_query_monitor(
        name="14. [CRITICAL] Coraza WAF Multi-Class High-Rate Attack Burst Detector (>=15 req/2m)",
        interval_mins=1,
        indices=["logs-waf-*"],
        query_dsl={
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-2m", "lte": "now"}}},
                        {"term": {"action.keyword": "blocked"}}
                    ]
                }
            },
            "aggs": {
                "by_class": {"terms": {"field": "owasp_category.keyword", "size": 5}},
                "top_paths": {"terms": {"field": "request_uri.keyword", "size": 5}},
                "top_ips": {"terms": {"field": "client_ip.keyword", "size": 5}}
            }
        },
        trigger_name="High-Rate Multi-Class Attack Burst (>= 15 Blocked Attacks in 2 Minutes)",
        severity="1",
        condition_script="ctx.results[0].hits.total.value >= 15",
        category="Coraza WAF & Multi-Vector Threat Protection",
        summary_template="High-rate coordinated multi-class attack burst detected and blocked by Coraza WAF! (Hit Rate: {{ctx.results.0.hits.total.value}} attacks in 2m | Peak Path: {{ctx.results.0.hits.hits.0._source.request_uri}} | Host: {{ctx.results.0.hits.hits.0._source.host}})",
        throttle_mins=15,
        details_template=burst_details
    ))

    return monitors


def sync_monitors():
    # Fetch existing monitors and delete old alerting monitors (skip security_analytics owned ones)
    search_body = {
        "size": 100,
        "query": {"match_all": {}}
    }
    existing = os_request("POST", "/_plugins/_alerting/monitors/_search", search_body)
    hits = existing.get("hits", {}).get("hits", [])
    for h in hits:
        m_id = h.get("_id")
        src = h.get("_source", {})
        m_name = src.get("name", "")
        owner = src.get("owner", "alerting")
        if owner == "security_analytics":
            continue
        os_request("DELETE", f"/_plugins/_alerting/monitors/{m_id}")
        print(f"[cleanup] Removed old monitor '{m_name}' ({m_id})")

    monitors = build_monitors()
    created_monitors = []
    for m in monitors:
        res = os_request("POST", "/_plugins/_alerting/monitors", m)
        m_id = res.get("_id")
        print(f"[monitor] Created '{m['name']}' -> ID: {m_id}")
        # Execute monitor once immediately to verify painless script & query syntax
        exec_res = os_request("POST", f"/_plugins/_alerting/monitors/{m_id}/_execute")
        err = exec_res.get("error") or exec_res.get("input_results", {}).get("error")
        trig_errs = [
            tr.get("error")
            for tr in exec_res.get("trigger_results", {}).values()
            if tr.get("error")
        ]
        print(f"          Test execution status: input_error={err}, trigger_errors={trig_errs}")
        created_monitors.append({"id": m_id, "monitor": m})

    export_path = "/home/kube/git/kube-homelab-infrastructure/kube/opensearch-alert-monitors.json"
    with open(export_path, "w") as f:
        json.dump(created_monitors, f, indent=2)
    print(f"[export] Saved {len(created_monitors)} monitor definitions to {export_path}")


if __name__ == "__main__":
    configure_alerting_settings()
    ensure_notification_channel()
    sync_monitors()
