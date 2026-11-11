"""Add the lab correlation data view and panels to the existing dashboard."""

import json
import urllib.request


BASE = "http://127.0.0.1:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
CORR_VIEW = "m6-correlation-view"
CORR_INDEX = "suricata-ai-correlated-lab"


def request(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read() or b"{}")


def visualization(title, field, kind="pie", metric="count"):
    params = {"type": kind, "addTooltip": True, "addLegend": True,
              "legendPosition": "right", "isDonut": kind == "pie"}
    aggs = [{"id": "1", "enabled": True, "type": metric, "params": {}, "schema": "metric"}]
    if field:
        aggs.append({"id": "2", "enabled": True, "type": "terms",
                     "params": {"field": field, "orderBy": "1", "order": "desc",
                                "size": 20, "otherBucket": False, "missingBucket": False},
                     "schema": "segment"})
    return {
        "title": title,
        "description": "Actual derived Milestone 6 correlation envelopes only.",
        "visState": json.dumps({"title": title, "type": kind, "params": params, "aggs": aggs}),
        "uiStateJSON": "{}",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
            "query": {"language": "kuery", "query": ""},
            "filter": [], "index": CORR_VIEW,
        })},
    }


def main():
    views = request("GET", "/api/data_views")
    view = next((v for v in views.get("data_view", []) if v.get("title") == CORR_INDEX), None)
    if view is None:
        view = request("POST", "/api/data_views/data_view", {
            "data_view": {"title": CORR_INDEX, "name": "Suricata AI Correlated Lab"}
        })["data_view"]
    global CORR_VIEW
    CORR_VIEW = view["id"]
    refs = []
    specs = [
        ("m6-runs-by-scenario", "Runs by scenario", "scenario"),
        ("m6-hybrid-by-run", "Hybrid classification by run", "hybrid_classification"),
        ("m6-sid-matches-by-run", "Suricata SID matches per run", "run_id"),
        ("m6-provenance-by-pcap", "PCAP and EVE SHA provenance", "pcap_sha256"),
        ("m6-correlation-status", "Correlation verification status", "correlation_status"),
        ("m6-safety-flags", "Review-only safety flags", "approved"),
    ]
    for ident, title, field in specs:
        request("POST", f"/api/saved_objects/visualization/{ident}?overwrite=true",
                 {"attributes": visualization(title, field),
                  "references": [{"id": CORR_VIEW,
                                  "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                                  "type": "index-pattern"}]})
        refs.append({"id": ident, "name": f"m6:{ident}", "type": "visualization"})
    dashboard = request("GET", "/api/saved_objects/dashboard/suricata-ai-ids-lab-dashboard")
    attrs = dashboard["attributes"]
    panels = json.loads(attrs["panelsJSON"])
    existing = {panel.get("panelIndex") for panel in panels}
    for index, (ident, title, _) in enumerate(specs, start=len(panels)):
        panel_id = f"m6-{index}"
        if panel_id in existing:
            continue
        panels.append({"version": "8.5.0", "type": "visualization",
                       "gridData": {"x": ((index - len(panels) + 6) % 2) * 24,
                                    "y": ((index - 6) // 2 + 4) * 12,
                                    "w": 24, "h": 11, "i": panel_id},
                       "panelIndex": panel_id, "embeddableConfig": {}, "title": title})
    attrs["panelsJSON"] = json.dumps(panels)
    dashboard_refs = dashboard.get("references", []) + refs
    request("PUT", "/api/saved_objects/dashboard/suricata-ai-ids-lab-dashboard?overwrite=true",
            {"attributes": attrs, "references": dashboard_refs})
    print(json.dumps({"data_view_id": CORR_VIEW, "dashboard": attrs["title"],
                      "panel_count": len(panels)}))


if __name__ == "__main__":
    main()
