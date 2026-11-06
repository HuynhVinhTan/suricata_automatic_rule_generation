import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.worker import (
    WORKER_SCHEMA_VERSION,
    build_manifest,
    run_worker,
    validate_manifest,
    write_elasticsearch_summary,
)


class WorkerContractTests(unittest.TestCase):

    def test_manifest_validation_rejects_mismatched_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.write_bytes(b"pcap-bytes")

            manifest = build_manifest(
                pcap=pcap,
                src="192.168.10.10",
                dst="192.168.10.20",
                run_id="run-001",
            )

            with self.assertRaises(ValueError):
                validate_manifest(
                    manifest,
                    pcap_path=pcap,
                    src="192.168.10.10",
                    dst="192.168.10.21",
                )

    def test_worker_run_success_with_fake_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "private"
            root.mkdir()
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"pcap-bytes")
            out_dir = root / "runs" / "run-001"

            def fake_processor(pcap_path, expected_sha, src, dst, private_root, output_dir):
                output_dir.mkdir(parents=True, exist_ok=False)
                (output_dir / "review.json").write_text(
                    json.dumps({
                        "status": "needs_review",
                        "deployable": False,
                        "deployed": False,
                        "model_sha256": "abc123",
                    }),
                    encoding="utf-8",
                )

            summary = run_worker(
                pcap=pcap,
                src="192.168.10.10",
                dst="192.168.10.20",
                private_root=root,
                output_dir=out_dir,
                processor=fake_processor,
            )

            self.assertEqual(summary["status"], "succeeded")
            self.assertEqual(summary["review_status"], "needs_review")
            self.assertEqual(summary["schema_version"], WORKER_SCHEMA_VERSION)
            self.assertTrue((out_dir / "worker_summary.json").exists())

    def test_elasticsearch_summary_writer_strips_sensitive_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "es" / "summary.json"
            doc = {
                "schema_version": WORKER_SCHEMA_VERSION,
                "run_id": "run-001",
                "status": "succeeded",
                "review_status": "needs_review",
                "pcap_sha256": "abc123",
                "source_ipv4": "192.168.10.10",
                "destination_ipv4": "192.168.10.20",
                "private_rule": "secret",
            }

            write_elasticsearch_summary(doc, destination)
            loaded = json.loads(destination.read_text(encoding="utf-8"))

            self.assertNotIn("private_rule", loaded)
            self.assertEqual(loaded["_index"], "suricata-ai-summary")
            self.assertEqual(loaded["status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
