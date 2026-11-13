#!/usr/bin/env python3
"""Provision only the showcase Kibana data view and dashboard."""

from __future__ import annotations

import json
import urllib.error
import urllib.request


BASE = "http://127.0.0.1:5601"
INDEX = "suricata-ai-showcase-*"
DATA_VIEW_ID = "suricata-ai-showcase"
DASHBOARD_ID = "suricata-ai-showcase-dashboard"


def request(method: str, path: str, payload: dict | None = None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=body, method=method, headers={
        "kbn-xsrf": "showcase", "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if method in {"POST", "PUT"} and exc.code == 409:
            return {"status": "already_exists"}
        raise


def visualization(title: str, kind: str, field: str | None = None, query: str = "") -> dict:
    if kind == "metric":
        aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
        vis_type = "metric"
        params = {}
    elif kind == "histogram":
        aggs = [{"id": "1", "enabled": True, "type": "histogram", "schema": "segment", "params": {"field": field, "interval": "auto", "min_doc_count": 1}}]
        vis_type = "histogram"
        params = {}
    else:
        raise ValueError(kind)
    state = {"title": title, "type": vis_type, "params": params, "aggs": aggs}
    search = {"query": {"language": "kuery", "query": query}, "filter": [], "index": DATA_VIEW_ID}
    return {"attributes": {
        "title": title, "visState": json.dumps(state), "uiStateJSON": "{}", "description": "Showcase-only; never production ELK.",
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search)},
    }, "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]}


def main() -> None:
    try:
        request("POST", "/api/data_views/data_view", {"data_view": {
            "id": DATA_VIEW_ID, "title": INDEX, "name": "Suricata AI Showcase", "timeFieldName": "event_time",
        }, "override": True})
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        request("PUT", f"/api/saved_objects/index-pattern/{DATA_VIEW_ID}?overwrite=true", {
            "attributes": {"title": INDEX, "name": "Suricata AI Showcase", "timeFieldName": "event_time"},
        })
    specs = [
        ("Showcase total flow predictions", "metric", None, ""),
        ("Showcase normal predictions", "metric", None, "ml.anomalous:false"),
        ("Showcase anomalous predictions", "metric", None, "ml.anomalous:true"),
        ("Showcase score distribution", "histogram", "ml.score", ""),
        ("Showcase predictions over time", "histogram", "event_time", ""),
        ("Showcase demo-only provenance", "metric", None, "provenance.demo_only:true"),
        ("Showcase review-only state", "metric", None, "review_state:REVIEW_ONLY"),
    ]
    refs = []
    for number, (title, kind, field, query) in enumerate(specs, 1):
        object_id = f"suricata-ai-showcase-viz-{number}"
        try:
            request("POST", f"/api/saved_objects/visualization/{object_id}", visualization(title, kind, field, query))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Kibana visualization {title} failed: {exc.read().decode()}") from exc
        refs.append({"id": object_id, "name": f"panel_{number}", "type": "visualization"})
    panels = []
    for number, reference in enumerate(refs, 1):
        panels.append({"version": "8.8.0", "type": "visualization", "gridData": {"x": ((number - 1) % 2) * 24, "y": ((number - 1) // 2) * 15, "w": 24, "h": 15, "i": str(number)}, "panelIndex": str(number), "embeddableConfig": {}, "panelRefName": reference["name"]})
    request("POST", f"/api/saved_objects/dashboard/{DASHBOARD_ID}", {"attributes": {
        "title": "Suricata AI Showcase", "description": "Seven-panel showcase_demo EVE acceptance dashboard.", "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}), "timeRestore": False, "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": [], "index": DATA_VIEW_ID})},
    }, "references": [{"name": reference["name"], "type": reference["type"], "id": reference["id"]} for reference in refs] + [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]})
    print(json.dumps({"index": INDEX, "data_view_id": DATA_VIEW_ID, "dashboard_id": DASHBOARD_ID, "panels": len(panels)}))


if __name__ == "__main__":
    main()
