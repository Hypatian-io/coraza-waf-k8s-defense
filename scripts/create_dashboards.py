#!/usr/bin/env python3
import json
import urllib.parse
import urllib.request

DASHBOARDS_URL = "http://192.168.2.243:5601"

def ensure_index_patterns():
    patterns = [
        ("logs-all", "logs-*"),
        ("logs-app-all", "logs-app-*"),
        ("logs-network-all", "logs-network-*"),
        ("logs-audit-all", "logs-audit-*"),
        ("logs-error-all", "logs-error-*"),
        ("logs-cluster-all", "logs-cluster-*"),
        ("metrics-cluster-all", "metrics-cluster-*"),
        ("alerts-history-all", "alerts-history-*"),
        ("logs-waf-all", "logs-waf-*"),
    ]
    created = []
    for idx_id, title in patterns:
        q = urllib.parse.urlencode([
            ("pattern", title),
            ("meta_fields", "_source"),
            ("meta_fields", "_id"),
            ("meta_fields", "_type"),
            ("meta_fields", "_index"),
            ("meta_fields", "_score"),
        ])
        with urllib.request.urlopen(f"{DASHBOARDS_URL}/api/index_patterns/_fields_for_wildcard?{q}") as resp:
            fields_data = json.loads(resp.read().decode("utf-8")).get("fields", [])
        created.append({
            "type": "index-pattern",
            "id": idx_id,
            "attributes": {
                "title": title,
                "timeFieldName": "@timestamp",
                "fields": json.dumps(fields_data)
            },
            "references": []
        })
    return created

def make_search_source(index_id, query=""):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
    })

def make_index_ref(index_id):
    return [{
        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "type": "index-pattern",
        "id": index_id
    }]

def vis_metric(vis_id, title, index_id, query=""):
    vis_state = {
        "title": title,
        "type": "metric",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": title}}
        ],
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 42}
            }
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_histogram(vis_id, title, index_id, split_field=None, split_label="Category", query=""):
    aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Log Events"}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {
            "field": "@timestamp",
            "useNormalizedOpenSearchInterval": True,
            "scaleMetricValues": False,
            "interval": "auto",
            "drop_partials": False,
            "min_doc_count": 1,
            "extended_bounds": {}
        }}
    ]
    if split_field:
        aggs.append({
            "id": "3", "enabled": True, "type": "terms", "schema": "group",
            "params": {"field": split_field, "size": 8, "order": "desc", "orderBy": "1", "customLabel": split_label}
        })
    vis_state = {
        "title": title,
        "type": "histogram",
        "aggs": aggs,
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Events"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"label": "Log Events", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_pie(vis_id, title, index_id, field, label, is_donut=True, query=""):
    vis_state = {
        "title": title,
        "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": field, "size": 10, "order": "desc", "orderBy": "1", "customLabel": label
            }}
        ],
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": is_donut,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_hbar(vis_id, title, index_id, field, label, query=""):
    vis_state = {
        "title": title,
        "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Count"}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": field, "size": 10, "order": "desc", "orderBy": "1", "customLabel": label
            }}
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left", "show": True, "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": False, "truncate": 200}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "bottom", "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "normal", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True,
            "addLegend": False,
            "legendPosition": "right"
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_coordinate_map(vis_id, title, index_id, geo_field="geoip.location", query="geoip.country_name:*"):
    vis_state = {
        "title": title,
        "type": "tile_map",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Requests"}},
            {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment", "params": {
                "field": geo_field,
                "autoPrecision": True,
                "precision": 2,
                "useGeocentroid": True,
                "isFilteredByCollar": True,
                "mapZoom": 2,
                "mapCenter": [20, 0]
            }}
        ],
        "params": {
            "mapType": "Scaled Circle Markers",
            "isDesaturated": False,
            "addTooltip": True,
            "heatClusterSize": 1.5,
            "legendPosition": "bottomright",
            "mapZoom": 2,
            "mapCenter": [20, 0],
            "wms": {
                "enabled": False,
                "options": {"format": "image/png", "transparent": True}
            }
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": json.dumps({"mapCenter": [20, 0], "mapZoom": 2}),
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_region_map(vis_id, title, index_id, iso_field="geoip.country_iso_code", query="geoip.country_iso_code:*"):
    vis_state = {
        "title": title,
        "type": "region_map",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Requests"}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": iso_field,
                "size": 50,
                "order": "desc",
                "orderBy": "1",
                "customLabel": "Country ISO Code"
            }}
        ],
        "params": {
            "legendPosition": "bottomright",
            "addTooltip": True,
            "colorSchema": "Yellow to Red",
            "selectedLayer": {
                "name": "World Countries",
                "id": "world_countries",
                " origin": "opensearch_vector_tile_map",
                "attribution": "Natural Earth",
                "format": {"type": "tms"},
                "fields": [
                    {"name": "iso2", "description": "ISO 3166-1 alpha-2 code"},
                    {"name": "name", "description": "Country name"}
                ]
            },
            "selectedJoinField": {"name": "iso2", "description": "ISO 3166-1 alpha-2 code"},
            "isDesaturated": False,
            "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": json.dumps({"mapCenter": [20, 0], "mapZoom": 1}),
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_geo_table(vis_id, title, index_id, query="client_ip:*"):
    vis_state = {
        "title": title,
        "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Requests"}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                "field": "client_ip.keyword", "size": 15, "order": "desc", "orderBy": "1", "customLabel": "Client IP"
            }},
            {"id": "3", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                "field": "geoip.country_name", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "Country", "missingBucket": True, "missingBucketLabel": "LAN / Internal"
            }},
            {"id": "4", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                "field": "geoip.city_name", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "City", "missingBucket": True, "missingBucketLabel": "-"
            }},
            {"id": "5", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                "field": "user_agent.keyword", "size": 5, "order": "desc", "orderBy": "1", "customLabel": "User-Agent", "missingBucket": True, "missingBucketLabel": "-"
            }}
        ],
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": True,
            "totalFunc": "sum"
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_table(vis_id, title, index_id, buckets, metric_label="Count", query=""):
    aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": metric_label}}
    ]
    for idx, b in enumerate(buckets, start=2):
        aggs.append({
            "id": str(idx),
            "enabled": True,
            "type": "terms",
            "schema": "bucket",
            "params": {
                "field": b["field"],
                "size": b.get("size", 10),
                "order": "desc",
                "orderBy": "1",
                "customLabel": b.get("label", b["field"]),
                "missingBucket": b.get("missingBucket", False),
                "missingBucketLabel": b.get("missingBucketLabel", "-")
            }
        })
    vis_state = {
        "title": title,
        "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": True,
            "totalFunc": "sum"
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_line_avg(vis_id, title, index_id, metric_field, metric_label, split_field="node.keyword", split_label="Node", query=""):
    aggs = [
        {"id": "1", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": metric_field, "customLabel": metric_label}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {
            "field": "@timestamp",
            "useNormalizedOpenSearchInterval": True,
            "scaleMetricValues": False,
            "interval": "auto",
            "drop_partials": False,
            "min_doc_count": 1,
            "extended_bounds": {}
        }},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {
            "field": split_field, "size": 10, "order": "desc", "orderBy": "1", "customLabel": split_label
        }}
    ]
    vis_state = {
        "title": title,
        "type": "line",
        "aggs": aggs,
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": metric_label}}],
            "seriesParams": [{"show": True, "type": "line", "mode": "normal", "data": {"label": metric_label, "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False
        }
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": title,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def vis_markdown_nav(vis_id):
    md = (
        "### Hypatian Kubernetes Observability, Coraza WAF & Alerting Suite\n"
        "**Dashboards:** "
        "[1. Cluster & Workload Health](/app/dashboards#/view/dashboard-cluster-health) | "
        "[2. Application Sidecar Logs](/app/dashboards#/view/dashboard-app-logs) | "
        "[3. Error & Exception Logs](/app/dashboards#/view/dashboard-error-logs) | "
        "[4. Network, Nginx, GeoIP & Ingress](/app/dashboards#/view/dashboard-network-logs) | "
        "[5. Security & K8s API Audit](/app/dashboards#/view/dashboard-audit-logs) | "
        "[6. Prometheus Metrics & Alerting](/app/dashboards#/view/dashboard-prometheus-alerts) | "
        "🛡️ **[7. Coraza WAF & OWASP Security](/app/dashboards#/view/dashboard-waf-logs)** | "
        "⚙️ **[Coraza WAF Console (`:8080`)](http://192.168.2.244:8080)** | "
        "🔔 **[Alerting Monitors](/app/alerting#/monitors)**"
    )
    vis_state = {
        "title": "Navigation Header",
        "type": "markdown",
        "aggs": [],
        "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": md}
    }
    return {
        "type": "visualization",
        "id": vis_id,
        "attributes": {
            "title": "Navigation Header",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "Suite Navigation Bar",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}
        },
        "references": []
    }

def saved_search(search_id, title, index_id, columns, query=""):
    return {
        "type": "search",
        "id": search_id,
        "attributes": {
            "title": title,
            "description": title,
            "hits": 0,
            "columns": columns,
            "sort": [["@timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": make_search_source(index_id, query)}
        },
        "references": make_index_ref(index_id)
    }

def build_dashboard(dash_id, title, description, panel_specs):
    panels = []
    refs = []
    for idx, p in enumerate(panel_specs, start=1):
        pid = str(idx)
        panels.append({
            "version": "2.19.7",
            "gridData": {"x": p["x"], "y": p["y"], "w": p["w"], "h": p["h"], "i": pid},
            "panelIndex": pid,
            "embeddableConfig": {"title": p["title"]},
            "panelRefName": f"panel_{pid}"
        })
        refs.append({
            "name": f"panel_{pid}",
            "type": p["type"],
            "id": p["id"]
        })
    return {
        "type": "dashboard",
        "id": dash_id,
        "attributes": {
            "title": title,
            "hits": 0,
            "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            }
        },
        "references": refs
    }

objects = ensure_index_patterns()
objects.append(vis_markdown_nav("vis-nav-header"))

# 1. CLUSTER & WORKLOAD HEALTH DASHBOARD (index: logs-cluster-all + metrics-cluster-all)
idx_cluster = "logs-cluster-all"
idx_metrics = "metrics-cluster-all"
idx_alerts = "alerts-history-all"

objects.extend([
    vis_metric("vis-cluster-total", "Total Cluster Health Events", idx_cluster),
    vis_metric("vis-cluster-systemd", "Kubelet & Containerd Events", idx_cluster, "_SYSTEMD_UNIT:*"),
    vis_line_avg("vis-prom-node-cpu", "Node CPU Utilization % (Prometheus)", idx_metrics, "cpu_usage_pct", "CPU %", "node.keyword", "Node", "metric_type: \"node_metrics\""),
    vis_line_avg("vis-prom-node-mem", "Node Memory Utilization % (Prometheus)", idx_metrics, "memory_usage_pct", "Memory %", "node.keyword", "Node", "metric_type: \"node_metrics\""),
    vis_line_avg("vis-prom-node-disk", "Node Root Filesystem Usage % (Prometheus)", idx_metrics, "disk_usage_pct", "Disk %", "node.keyword", "Node", "metric_type: \"node_metrics\""),
    vis_line_avg("vis-prom-pvc-disk", "Longhorn PVC Storage Usage % (Prometheus)", idx_metrics, "volume_usage_pct", "PVC %", "pvc.keyword", "PVC", "metric_type: \"pvc_metrics\""),
    vis_line_avg("vis-prom-pod-mem", "Top Pod Memory Working Set MB (Prometheus)", idx_metrics, "memory_mb", "Memory MB", "pod.keyword", "Pod", "metric_type: \"pod_metrics\""),
    vis_histogram("vis-cluster-timeline", "Cluster Log Volume Over Time by Namespace", idx_cluster, "kubernetes.namespace_name.keyword", "Namespace"),
    vis_pie("vis-cluster-ns-pie", "Workload Logs by Namespace", idx_cluster, "kubernetes.namespace_name.keyword", "Namespace"),
    vis_pie("vis-cluster-node-pie", "Log Distribution by Cluster Node", idx_cluster, "kubernetes.host.keyword", "Node"),
    vis_hbar("vis-cluster-top-pods", "Top Active Pods Across Cluster", idx_cluster, "kubernetes.pod_name.keyword", "Pod"),
    saved_search("search-cluster-stream", "Live Cluster & Workload Health Log Stream", idx_cluster,
                 ["kubernetes.namespace_name", "kubernetes.pod_name", "kubernetes.host", "stream", "log"])
])
objects.append(build_dashboard(
    "dashboard-cluster-health",
    "1. Cluster & Workload Health Dashboard",
    "Real-time Kubernetes cluster, Prometheus Node CPU/Memory/Disk metrics, systemd (kubelet/containerd), and workload health logs",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-cluster-total", "type": "visualization", "title": "Total Cluster Events", "x": 0, "y": 4, "w": 12, "h": 8},
        {"id": "vis-cluster-systemd", "type": "visualization", "title": "Kubelet & Containerd Systemd Logs", "x": 12, "y": 4, "w": 12, "h": 8},
        {"id": "vis-cluster-ns-pie", "type": "visualization", "title": "Logs by Namespace", "x": 24, "y": 4, "w": 12, "h": 12},
        {"id": "vis-cluster-node-pie", "type": "visualization", "title": "Logs by Node", "x": 36, "y": 4, "w": 12, "h": 12},
        {"id": "vis-cluster-timeline", "type": "visualization", "title": "Cluster Log Volume Over Time by Namespace", "x": 0, "y": 12, "w": 24, "h": 12},
        {"id": "vis-cluster-top-pods", "type": "visualization", "title": "Top Active Pods", "x": 24, "y": 16, "w": 24, "h": 8},
        {"id": "vis-prom-node-cpu", "type": "visualization", "title": "Node CPU Utilization % (Prometheus)", "x": 0, "y": 24, "w": 16, "h": 11},
        {"id": "vis-prom-node-mem", "type": "visualization", "title": "Node Memory Utilization % (Prometheus)", "x": 16, "y": 24, "w": 16, "h": 11},
        {"id": "vis-prom-node-disk", "type": "visualization", "title": "Node Root Disk Usage % (Prometheus)", "x": 32, "y": 24, "w": 16, "h": 11},
        {"id": "search-cluster-stream", "type": "search", "title": "Live Cluster & Workload Health Logs", "x": 0, "y": 35, "w": 48, "h": 18},
    ]
))

# 2. APPLICATION SIDECAR LOGS DASHBOARD (index: logs-app-all)
idx_app = "logs-app-all"
objects.extend([
    vis_metric("vis-app-total", "Total Sidecar Application Logs", idx_app),
    vis_metric("vis-app-azaan", "Azaan Station Events", idx_app, "app: \"azaan-app\""),
    vis_metric("vis-app-mariadb", "MariaDB Galera Events", idx_app, "app: \"mariadb-galera\""),
    vis_metric("vis-app-webapp", "Hypatian Web App & HomeAssistant Events", idx_app, "app: \"hypatian-web-app\" or app: \"homeassistant\""),
    vis_histogram("vis-app-timeline", "Application Log Volume Over Time (by Workload)", idx_app, "app.keyword", "Application"),
    vis_pie("vis-app-pie", "Logs by Sidecar Application", idx_app, "app.keyword", "Application"),
    vis_hbar("vis-app-pods", "Application Logs by Pod Instance", idx_app, "pod.keyword", "Pod"),
    saved_search("search-app-stream", "Live Application Sidecar Log Stream", idx_app,
                 ["app", "pod", "node", "shipper", "log"])
])
objects.append(build_dashboard(
    "dashboard-app-logs",
    "2. Application Sidecar Logs Dashboard",
    "Application logs shipped via Fluent Bit sidecar containers from hypatian-web-app, azaan-app, homeassistant, and mariadb-galera",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-app-total", "type": "visualization", "title": "Total Sidecar App Logs", "x": 0, "y": 4, "w": 12, "h": 7},
        {"id": "vis-app-azaan", "type": "visualization", "title": "Azaan Station Logs", "x": 12, "y": 4, "w": 12, "h": 7},
        {"id": "vis-app-mariadb", "type": "visualization", "title": "MariaDB Galera Logs", "x": 24, "y": 4, "w": 12, "h": 7},
        {"id": "vis-app-webapp", "type": "visualization", "title": "Web App & HomeAssistant Logs", "x": 36, "y": 4, "w": 12, "h": 7},
        {"id": "vis-app-timeline", "type": "visualization", "title": "Application Log Timeline by Workload", "x": 0, "y": 11, "w": 24, "h": 12},
        {"id": "vis-app-pie", "type": "visualization", "title": "Distribution by Application", "x": 24, "y": 11, "w": 12, "h": 12},
        {"id": "vis-app-pods", "type": "visualization", "title": "Logs by Pod Instance", "x": 36, "y": 11, "w": 12, "h": 12},
        {"id": "search-app-stream", "type": "search", "title": "Live Application Sidecar Logs", "x": 0, "y": 23, "w": 48, "h": 18},
    ]
))

# 3. ERROR & EXCEPTION LOGS DASHBOARD (index: logs-error-all)
idx_err = "logs-error-all"
objects.extend([
    vis_metric("vis-err-total", "Total Error & Warning Events", idx_err),
    vis_histogram("vis-err-timeline", "Error Spikes Over Time by Namespace", idx_err, "kubernetes.namespace_name.keyword", "Namespace"),
    vis_pie("vis-err-ns-pie", "Errors by Namespace", idx_err, "kubernetes.namespace_name.keyword", "Namespace"),
    vis_hbar("vis-err-pods-bar", "Top Error-Emitting Pods", idx_err, "kubernetes.pod_name.keyword", "Pod"),
    vis_pie("vis-err-node-pie", "Errors by Host Node", idx_err, "kubernetes.host.keyword", "Node"),
    saved_search("search-err-stream", "Live Error & Exception Log Stream", idx_err,
                 ["kubernetes.namespace_name", "kubernetes.pod_name", "kubernetes.host", "app", "log"])
])
objects.append(build_dashboard(
    "dashboard-error-logs",
    "3. Error & Exception Logs Dashboard",
    "Centralized error, exception, traceback, CrashLoopBackOff, and HTTP 4xx/5xx events across all workloads and cluster components",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-err-total", "type": "visualization", "title": "Total Error Events", "x": 0, "y": 4, "w": 12, "h": 10},
        {"id": "vis-err-ns-pie", "type": "visualization", "title": "Errors by Namespace", "x": 12, "y": 4, "w": 18, "h": 10},
        {"id": "vis-err-node-pie", "type": "visualization", "title": "Errors by Node", "x": 30, "y": 4, "w": 18, "h": 10},
        {"id": "vis-err-timeline", "type": "visualization", "title": "Error Rate Over Time", "x": 0, "y": 14, "w": 28, "h": 12},
        {"id": "vis-err-pods-bar", "type": "visualization", "title": "Top Pods Generating Errors", "x": 28, "y": 14, "w": 20, "h": 12},
        {"id": "search-err-stream", "type": "search", "title": "Live Error & Exception Log Stream", "x": 0, "y": 26, "w": 48, "h": 18},
    ]
))

# 4. NETWORK, NGINX REQUESTS, GEOIP & INGRESS DASHBOARD (index: logs-network-all)
idx_net = "logs-network-all"
objects.extend([
    vis_metric("vis-net-total", "Total Network & Ingress Events", idx_net),
    vis_metric("vis-net-nginx-req", "Nginx HTTP Requests (Sidecars)", idx_net, "shipper: \"sidecar\""),
    vis_metric("vis-net-geoip-req", "GeoIP-Resolved External Requests", idx_net, "geoip.country_name:*"),
    vis_coordinate_map("vis-net-world-map", "Live Global Request Origin Map (GeoIP Coordinates)", idx_net, "geoip.location", "geoip.country_name:*"),
    vis_region_map("vis-net-region-map", "Global Request Choropleth Map by Country", idx_net, "geoip.country_iso_code", "geoip.country_iso_code:*"),
    vis_pie("vis-net-geo-countries", "Requests by Originating Country", idx_net, "geoip.country_name", "Country", query="geoip.country_name:*"),
    vis_hbar("vis-net-geo-cities", "Top Originating Cities", idx_net, "geoip.city_name", "City", query="geoip.city_name:*"),
    vis_hbar("vis-net-top-ips", "Top Originating Client IPs", idx_net, "client_ip.keyword", "Client IP", query="client_ip:*"),
    vis_hbar("vis-net-top-ua", "Top Client User-Agents", idx_net, "user_agent.keyword", "User-Agent", query="user_agent:*"),
    vis_geo_table("vis-net-geo-table", "Client IP, GeoIP Location & User-Agent Breakdown", idx_net, query="client_ip:*"),
    vis_histogram("vis-net-timeline", "Network & HTTP Traffic Over Time", idx_net, "app.keyword", "Service"),
    vis_pie("vis-net-status-pie", "HTTP Status Codes (Nginx & Traefik)", idx_net, "status", "HTTP Status", query="status:*"),
    vis_hbar("vis-net-top-uri", "Top Requested HTTP URIs", idx_net, "request_uri.keyword", "Request URI", query="request_uri:*"),
    vis_pie("vis-net-pods-pie", "Cluster Network Components (Traefik / MetalLB / Flannel / CoreDNS)", idx_net, "kubernetes.pod_name.keyword", "Network Pod"),
    saved_search("search-net-nginx", "Nginx & Ingress HTTP Request Log Stream (with GeoIP & User-Agent)", idx_net,
                 ["app", "host", "client_ip", "geoip.country_name", "geoip.city_name", "request_method", "request_uri", "status", "user_agent"],
                 query="shipper: \"sidecar\" or app: \"traefik-ingress\""),
    saved_search("search-net-all", "All Network & SDN Log Stream (Traefik, MetalLB, Flannel, CoreDNS)", idx_net,
                 ["kubernetes.namespace_name", "kubernetes.pod_name", "app", "client_ip", "request_uri", "status", "log"])
])
objects.append(build_dashboard(
    "dashboard-network-logs",
    "4. Network, Nginx Requests & Ingress Dashboard",
    "Live Global GeoIP Maps, Top Client IPs, Top User-Agents, Originating Countries/Cities, Nginx & Traefik HTTP requests, and SDN logs",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-net-total", "type": "visualization", "title": "Total Network Events", "x": 0, "y": 4, "w": 8, "h": 8},
        {"id": "vis-net-nginx-req", "type": "visualization", "title": "Nginx Sidecar HTTP Requests", "x": 8, "y": 4, "w": 8, "h": 8},
        {"id": "vis-net-geoip-req", "type": "visualization", "title": "GeoIP-Resolved Public Requests", "x": 16, "y": 4, "w": 8, "h": 8},
        {"id": "vis-net-status-pie", "type": "visualization", "title": "HTTP Status Code Breakdown", "x": 24, "y": 4, "w": 12, "h": 8},
        {"id": "vis-net-geo-countries", "type": "visualization", "title": "Requests by Country", "x": 36, "y": 4, "w": 12, "h": 8},
        {"id": "vis-net-world-map", "type": "visualization", "title": "Live Global Request Origin Map (GeoIP Coordinates)", "x": 0, "y": 12, "w": 24, "h": 15},
        {"id": "vis-net-region-map", "type": "visualization", "title": "Global Choropleth Map by Originating Country", "x": 24, "y": 12, "w": 24, "h": 15},
        {"id": "vis-net-top-ips", "type": "visualization", "title": "Top Originating Client IPs", "x": 0, "y": 27, "w": 16, "h": 11},
        {"id": "vis-net-geo-cities", "type": "visualization", "title": "Top Originating Cities", "x": 16, "y": 27, "w": 16, "h": 11},
        {"id": "vis-net-top-ua", "type": "visualization", "title": "Top Client User-Agents", "x": 32, "y": 27, "w": 16, "h": 11},
        {"id": "vis-net-geo-table", "type": "visualization", "title": "Client IP, GeoIP Location & User-Agent Intelligence Table", "x": 0, "y": 38, "w": 48, "h": 12},
        {"id": "vis-net-timeline", "type": "visualization", "title": "Network Traffic Over Time", "x": 0, "y": 50, "w": 20, "h": 11},
        {"id": "vis-net-top-uri", "type": "visualization", "title": "Top Requested HTTP URIs", "x": 20, "y": 50, "w": 16, "h": 11},
        {"id": "vis-net-pods-pie", "type": "visualization", "title": "Network Infrastructure Pods", "x": 36, "y": 50, "w": 12, "h": 11},
        {"id": "search-net-nginx", "type": "search", "title": "Nginx & Traefik HTTP Request Logs (with GeoIP & User-Agent)", "x": 0, "y": 61, "w": 48, "h": 14},
        {"id": "search-net-all", "type": "search", "title": "Full Network Infrastructure Log Stream", "x": 0, "y": 75, "w": 48, "h": 14},
    ]
))

# 5. SECURITY & KUBERNETES API AUDIT DASHBOARD (index: logs-audit-all)
idx_audit = "logs-audit-all"
objects.extend([
    vis_metric("vis-audit-total", "Total Security & API Audit Events", idx_audit),
    vis_metric("vis-audit-secrets", "Secret & Token Access Events", idx_audit, "objectRef.resource: \"secrets\" or objectRef.resource: \"serviceaccounts\""),
    vis_histogram("vis-audit-timeline", "Audit Activity Over Time by API Verb", idx_audit, "verb.keyword", "API Verb"),
    vis_pie("vis-audit-verbs-pie", "Kubernetes API Audit Events by Verb", idx_audit, "verb.keyword", "Verb"),
    vis_pie("vis-audit-resources-pie", "Audited Target Resources (Secrets, Pods, RBAC, etc.)", idx_audit, "objectRef.resource.keyword", "Resource"),
    vis_hbar("vis-audit-users-bar", "Top Authenticated Users & ServiceAccounts", idx_audit, "user.username.keyword", "User / ServiceAccount"),
    vis_pie("vis-audit-status-pie", "API Response Status Codes", idx_audit, "responseStatus.code", "HTTP Status"),
    saved_search("search-audit-stream", "Live Kubernetes API & Host Security Audit Log Stream", idx_audit,
                 ["verb", "user.username", "objectRef.namespace", "objectRef.resource", "responseStatus.code", "requestURI", "sourceIPs"])
])
objects.append(build_dashboard(
    "dashboard-audit-logs",
    "5. Security & Kubernetes API Audit Dashboard",
    "Kubernetes kube-apiserver audit trail (RBAC, secret access, workload mutations, verbs, users, status codes) and host SSH/sudo auth logs",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-audit-total", "type": "visualization", "title": "Total Audit Events", "x": 0, "y": 4, "w": 12, "h": 8},
        {"id": "vis-audit-secrets", "type": "visualization", "title": "Secret & Token Access Events", "x": 12, "y": 4, "w": 12, "h": 8},
        {"id": "vis-audit-verbs-pie", "type": "visualization", "title": "Audit Events by API Verb", "x": 24, "y": 4, "w": 12, "h": 11},
        {"id": "vis-audit-status-pie", "type": "visualization", "title": "API Response Status Codes", "x": 36, "y": 4, "w": 12, "h": 11},
        {"id": "vis-audit-timeline", "type": "visualization", "title": "Audit Activity Over Time by Verb", "x": 0, "y": 12, "w": 24, "h": 12},
        {"id": "vis-audit-resources-pie", "type": "visualization", "title": "Audited Kubernetes Resources", "x": 24, "y": 15, "w": 12, "h": 9},
        {"id": "vis-audit-users-bar", "type": "visualization", "title": "Top Users & ServiceAccounts", "x": 36, "y": 15, "w": 12, "h": 9},
        {"id": "search-audit-stream", "type": "search", "title": "Live Kubernetes API & Security Audit Log Stream", "x": 0, "y": 24, "w": 48, "h": 18},
    ]
))

# 6. PROMETHEUS METRICS & ALERTING DASHBOARD (index: metrics-cluster-all + alerts-history-all)
objects.extend([
    vis_metric("vis-prom-total-samples", "Prometheus Metric Samples", idx_metrics),
    vis_metric("vis-alerts-total", "Triggered Alerts (alert@hypatian.io -> saad@hypatian.io)", idx_alerts),
    vis_pie("vis-alerts-by-crit", "Triggered Alerts by Criticality", idx_alerts, "criticality.keyword", "Criticality"),
    saved_search("search-alerts-stream", "Dispatched Alert History (alert@hypatian.io -> saad@hypatian.io)", idx_alerts,
                 ["criticality", "monitor_name", "trigger_name", "category", "sender", "recipient", "summary"]),
    saved_search("search-prom-node-stream", "Live Prometheus Node Resource Metrics (CPU %, RAM %, Disk %)", idx_metrics,
                 ["node", "cpu_usage_pct", "memory_usage_pct", "memory_avail_mb", "disk_usage_pct", "disk_avail_gb", "load_1m", "node_ready"],
                 query="metric_type: \"node_metrics\"")
])
objects.append(build_dashboard(
    "dashboard-prometheus-alerts",
    "6. Prometheus Metrics & Alerting Dashboard",
    "Prometheus Node CPU %, Memory %, Root Disk %, Longhorn PVC Storage %, Pod Memory MB, and Dispatched AWS SES Alert History (alert@hypatian.io -> saad@hypatian.io)",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-prom-total-samples", "type": "visualization", "title": "Prometheus Metric Samples", "x": 0, "y": 4, "w": 14, "h": 8},
        {"id": "vis-alerts-total", "type": "visualization", "title": "Dispatched Alerts (alert@hypatian.io)", "x": 14, "y": 4, "w": 14, "h": 8},
        {"id": "vis-alerts-by-crit", "type": "visualization", "title": "Alerts by Criticality Tier", "x": 28, "y": 4, "w": 20, "h": 8},
        {"id": "vis-prom-node-cpu", "type": "visualization", "title": "Node CPU Utilization % (Prometheus)", "x": 0, "y": 12, "w": 24, "h": 12},
        {"id": "vis-prom-node-mem", "type": "visualization", "title": "Node Memory Utilization % (Prometheus)", "x": 24, "y": 12, "w": 24, "h": 12},
        {"id": "vis-prom-node-disk", "type": "visualization", "title": "Node Root Filesystem Usage % (Prometheus)", "x": 0, "y": 24, "w": 16, "h": 12},
        {"id": "vis-prom-pvc-disk", "type": "visualization", "title": "Longhorn PVC Storage Usage % (Prometheus)", "x": 16, "y": 24, "w": 16, "h": 12},
        {"id": "vis-prom-pod-mem", "type": "visualization", "title": "Top Pod Memory Working Set MB (Prometheus)", "x": 32, "y": 24, "w": 16, "h": 12},
        {"id": "search-alerts-stream", "type": "search", "title": "Alert History (Sent from alert@hypatian.io to saad@hypatian.io)", "x": 0, "y": 36, "w": 48, "h": 12},
        {"id": "search-prom-node-stream", "type": "search", "title": "Live Prometheus Node Resource Metrics Stream", "x": 0, "y": 48, "w": 48, "h": 14},
    ]
))

# 7. CORAZA WAF & OWASP THREAT INTELLIGENCE DASHBOARD (index: logs-waf-all + alerts-history-all)
idx_waf = "logs-waf-all"
objects.extend([
    vis_metric("vis-waf-total", "Total WAF Inspected Requests", idx_waf),
    vis_metric("vis-waf-blocked", "Attacks Blocked by Coraza (HTTP 403)", idx_waf, "action: \"blocked\""),
    vis_metric("vis-waf-critical", "Critical OWASP Top 10 Attacks", idx_waf, "severity: \"CRITICAL\""),
    vis_metric("vis-waf-rule100020-blocks", "Rule 100020 IP Blocklist Drops", idx_waf, "rule_id: 100020"),
    vis_coordinate_map("vis-waf-world-map", "Live Global WAF Attack Origin Map (GeoIP Coordinates)", idx_waf, "geoip.location", "action: \"blocked\" and geoip.country_name:*"),
    vis_region_map("vis-waf-region-map", "Global Attack Choropleth Map by Country", idx_waf, "geoip.country_iso_code", "action: \"blocked\" and geoip.country_iso_code:*"),
    vis_histogram("vis-waf-timeline", "WAF Traffic & Blocked Attacks Over Time", idx_waf, "action.keyword", "WAF Action"),
    vis_pie("vis-waf-owasp-pie", "Blocked Attacks by OWASP Top 10 Category", idx_waf, "owasp_top10.keyword", "OWASP Top 10", query="action: \"blocked\""),
    vis_pie("vis-waf-cat-pie", "Blocked Attacks by CRS Threat Vector", idx_waf, "owasp_category.keyword", "Threat Category", query="action: \"blocked\""),
    vis_hbar("vis-waf-top-ips", "Top Attacking External Client IPs", idx_waf, "client_ip.keyword", "Attacking IP", query="action: \"blocked\""),
    vis_hbar("vis-waf-top-rules", "Top Triggered Coraza SecRule Signatures", idx_waf, "rule_msg.keyword", "SecRule Message", query="action: \"blocked\""),
    vis_hbar("vis-waf-top-uris", "Top Targeted URIs Under Attack", idx_waf, "request_uri.keyword", "Targeted URI", query="action: \"blocked\""),
    vis_table("vis-waf-blocked-attribution-table", "Blocked Attacker IPs, Exploit Reasoning & Geolocation Breakdown", idx_waf, [
        {"field": "client_ip.keyword", "size": 15, "label": "Attacking Client IP"},
        {"field": "geoip.country_name", "size": 5, "label": "Country", "missingBucket": True, "missingBucketLabel": "LAN / Internal"},
        {"field": "geoip.city_name", "size": 5, "label": "City", "missingBucket": True, "missingBucketLabel": "-"},
        {"field": "owasp_category.keyword", "size": 5, "label": "Attack Vector / Reasoning"},
        {"field": "rule_msg.keyword", "size": 5, "label": "Triggered SecRule"},
        {"field": "request_uri.keyword", "size": 5, "label": "Targeted URI Path"}
    ], metric_label="Attacks Blocked", query="action: \"blocked\""),
    saved_search("search-waf-auto-blocked-table", "Permanently Blocked IPs, Attack Thresholds & Automated Defense (>5 Attacks in 15m)", idx_alerts,
                 ["@timestamp", "blocked_ip", "peak_15m_attacks", "total_attacks", "criticality", "attack_classes", "top_paths", "summary"],
                 query="category: \"Coraza WAF Automated IP Defense\" or monitor_name: \"Coraza WAF Automated Attacker IP Blocker\""),
    saved_search("search-waf-blocked-payloads", "Blocked Exploit Payloads, Malicious Signatures & GeoIP Telemetry", idx_waf,
                 ["@timestamp", "client_ip", "geoip.country_name", "geoip.city_name", "owasp_category", "rule_id", "rule_msg", "matched_data", "request_uri", "status"],
                 query="action: \"blocked\""),
    saved_search("search-waf-all", "All Coraza WAF Inspected Requests Stream", idx_waf,
                 ["action", "status", "severity", "owasp_category", "client_ip", "request_method", "request_uri", "user_agent", "latency_ms"])
])
objects.append(build_dashboard(
    "dashboard-waf-logs",
    "7. Coraza WAF & OWASP Threat Intelligence Dashboard",
    "Coraza v3 Web Application Firewall (OWASP CRS) real-time attack blocking, Global Attack GeoIP maps, OWASP Top 10 breakdown, permanently blocked IPs, attack thresholds, exploit payloads, and audit stream",
    [
        {"id": "vis-nav-header", "type": "visualization", "title": "Navigation", "x": 0, "y": 0, "w": 48, "h": 4},
        {"id": "vis-waf-total", "type": "visualization", "title": "Total WAF Inspected Requests", "x": 0, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-blocked", "type": "visualization", "title": "Blocked Attacks (HTTP 403)", "x": 8, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-critical", "type": "visualization", "title": "Critical OWASP Attacks", "x": 16, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-rule100020-blocks", "type": "visualization", "title": "Rule 100020 IP Blocklist Drops", "x": 24, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-owasp-pie", "type": "visualization", "title": "OWASP Top 10 Breakdown", "x": 32, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-cat-pie", "type": "visualization", "title": "CRS Attack Vector Breakdown", "x": 40, "y": 4, "w": 8, "h": 7},
        {"id": "vis-waf-timeline", "type": "visualization", "title": "WAF Traffic & Blocked Attacks Timeline", "x": 0, "y": 11, "w": 24, "h": 10},
        {"id": "vis-waf-region-map", "type": "visualization", "title": "Global Attack Choropleth Map by Country", "x": 24, "y": 11, "w": 24, "h": 22},
        {"id": "vis-waf-world-map", "type": "visualization", "title": "Live Global WAF Attack Origin Map (GeoIP Coordinates)", "x": 0, "y": 21, "w": 24, "h": 12},
        {"id": "vis-waf-top-ips", "type": "visualization", "title": "Top Attacking Client IPs", "x": 0, "y": 33, "w": 16, "h": 10},
        {"id": "vis-waf-top-rules", "type": "visualization", "title": "Top Triggered Coraza SecRules", "x": 16, "y": 33, "w": 16, "h": 10},
        {"id": "vis-waf-top-uris", "type": "visualization", "title": "Top Targeted URIs", "x": 32, "y": 33, "w": 16, "h": 10},
        {"id": "search-waf-auto-blocked-table", "type": "search", "title": "Permanently Blocked IPs, Attack Thresholds & Automated Defense (>5 Attacks in 15m)", "x": 0, "y": 43, "w": 48, "h": 12},
        {"id": "vis-waf-blocked-attribution-table", "type": "visualization", "title": "Blocked Attacker IPs, Exploit Reasoning & Geolocation Breakdown", "x": 0, "y": 55, "w": 48, "h": 14},
        {"id": "search-waf-blocked-payloads", "type": "search", "title": "Blocked Exploit Payloads, Malicious Signatures & GeoIP Telemetry", "x": 0, "y": 69, "w": 48, "h": 14},
        {"id": "search-waf-all", "type": "search", "title": "All Coraza WAF Inspected Requests Stream", "x": 0, "y": 83, "w": 48, "h": 14},
    ]
))

with open("/home/kube/git/kube-homelab-infrastructure/kube/opensearch-dashboards-objects.json", "w") as f:
    json.dump(objects, f, indent=2)

req = urllib.request.Request(
    f"{DASHBOARDS_URL}/api/saved_objects/_bulk_create?overwrite=true",
    data=json.dumps(objects).encode("utf-8"),
    headers={"osd-xsrf": "true", "Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read().decode("utf-8"))
    saved = result.get("saved_objects", [])
    errors = [x for x in saved if "error" in x]
    print(f"Successfully imported {len(saved) - len(errors)}/{len(saved)} Saved Objects (errors: {len(errors)})")
    if errors:
        print("Errors:", errors[:2])
