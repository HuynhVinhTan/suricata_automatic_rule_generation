"""Index derived Milestone 6 envelopes into the lab-only correlation index."""

import json
import sys
import urllib.error
import urllib.request


INDEX = "suricata-ai-correlated-lab"
BASE = "http://127.0.0.1:9200"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main():
    mapping = {
        "mappings": {
            "properties": {
                field: {"type": kind}
                for field, kind in {
                    "run_id": "keyword", "scenario": "keyword",
                    "pcap_sha256": "keyword", "manifest_sha256": "keyword",
                    "eve_output_sha256": "keyword", "ai_summary_sha256": "keyword",
                    "ai_summary_document_id": "keyword", "model_sha256": "keyword",
                    "calibration_sha256": "keyword", "hybrid_classification": "keyword",
                    "review_status": "keyword", "sid": "integer",
                    "matching_eve_events": "integer", "matched_flows": "integer",
                    "approved": "boolean", "deployable": "boolean", "deployed": "boolean",
                    "correlation_level": "keyword", "correlation_verified": "boolean",
                    "ai_summary_indexed": "boolean", "correlation_status": "keyword",
                    "native_eve_preserved": "boolean", "document_id": "keyword",
                }.items()
            }
        }
    }
    status, body = call("PUT", "/" + INDEX, mapping)
    print("create_index", status, body.get("acknowledged", body.get("error", {}).get("type")))
    for document in json.load(sys.stdin):
        path = f"/{INDEX}/_doc/{document['document_id']}?op_type=create"
        status, body = call("PUT", path, document)
        if status == 409:
            get_status, existing = call("GET", f"/{INDEX}/_doc/{document['document_id']}")
            print(document["run_id"], "duplicate_verified", get_status == 200 and existing.get("_source") == document)
        elif 200 <= status < 300:
            print(document["run_id"], "indexed", status)
        else:
            print(document["run_id"], "failed", status, body)
    call("POST", "/" + INDEX + "/_refresh")
    _, body = call("GET", "/" + INDEX + "/_count")
    print("count", body.get("count"))


if __name__ == "__main__":
    main()
