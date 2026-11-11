"""Create the revised Suricata acceptance report from frozen evidence."""

from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt


OUT = Path("reports/suricata_ai_acceptance_report_revised.docx")


def table(doc, headers, rows):
    t = doc.add_table(rows=1, cols=len(headers))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.style = "Table Grid"
    for cell, value in zip(t.rows[0].cells, headers):
        cell.text = str(value)
    for row in rows:
        cells = t.add_row().cells
        for cell, value in zip(cells, row):
            cell.text = str(value)
    return t


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Inches(0.7)
    sec.bottom_margin = Inches(0.7)
    sec.left_margin = Inches(0.7)
    sec.right_margin = Inches(0.7)
    styles = doc.styles
    styles["Normal"].font.name = "Arial"
    styles["Normal"].font.size = Pt(9)
    styles["Title"].font.name = "Arial"
    styles["Title"].font.size = Pt(22)
    styles["Heading 1"].font.name = "Arial"
    styles["Heading 1"].font.size = Pt(15)
    styles["Heading 2"].font.name = "Arial"
    styles["Heading 2"].font.size = Pt(11)

    title = doc.add_paragraph(style="Title")
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("Suricata AI IDS Acceptance Report")
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run("Revised evidence report - 11 November 2026").italic = True

    doc.add_heading("Executive result", level=1)
    doc.add_paragraph(
        "Automatic rule generation, provenance metadata, review-only transfer, replay rejection, "
        "and isolated Suricata validation are implemented. The frozen-model candidate SID 9103001 "
        "was rejected because it produced 78 alerts on Attack and 78 alerts on Normal. It is not "
        "presented as a successful detection rule."
    )

    doc.add_heading("Run provenance", level=1)
    table(doc, ["Item", "Value"], [
        ("Worker run", "vm3-rulegen-v02"),
        ("Attack PCAP SHA256", "681b5e263ac11dc8a4cd1cca80a3b0ced480ce97e0105eaae4595f2c8e97675c"),
        ("Normal PCAP SHA256", "bb762a4243455a6388012d9fd733e6d7cd265507a276ad4f97f75e40422286a8"),
        ("Frozen model SHA256", "206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d"),
        ("Generated SID", "9103001"),
        ("Decision", "rejected_validation_failure / normal_replay_false_positive"),
    ])

    doc.add_heading("Implemented automatic rule generation", level=1)
    doc.add_paragraph(
        "The worker derives a candidate from the current inference result, allocates a fresh SID "
        "with collision checks, writes a separate ml-generated.rules artifact, and writes metadata "
        "containing run ID, PCAP SHA256, model SHA256, rule SHA256, threshold evidence, review status, "
        "and approval/deployment flags. Review-only mode does not publish to production. The generated "
        "candidate used flags:S and detection_filter:track by_src,count 3,seconds 10. This counts "
        "matching SYN packets per source and does not count unique destination ports."
    )

    doc.add_heading("Attack versus Normal investigation", level=1)
    table(doc, ["Evidence", "Recon V03 / Attack", "Normal Matched12 V02 / Normal"], [
        ("Packets", "964", "960"),
        ("Initial SYN packets", "96", "96"),
        ("Unique destination ports", "12", "12"),
        ("10-second SYN windows", "17, 17, 16, 17, 16, 13", "17, 15, 16, 17, 16, 15"),
        ("Mean inter-SYN interval", "604.049 ms", "621.302 ms"),
        ("Completed handshakes", "96", "96"),
        ("Bidirectional payload flows", "96", "96"),
        ("RST responses", "0", "0"),
        ("HTTP GET / 200", "96", "96"),
    ])
    doc.add_paragraph(
        "Attack paths were /version, /status, /metrics, and /admin, 24 each. Normal used /health, "
        "96 requests. The path difference alone does not establish that /admin is malicious. The "
        "transport evidence is effectively identical, so no reliable distinguishing pattern was found "
        "for the SYN-burst candidate. Models and thresholds were not changed."
    )

    doc.add_heading("Baseline and augmented EVE results", level=1)
    table(doc, ["Replay", "Alerts", "Alert signatures", "Flow", "HTTP"], [
        ("Baseline Attack", "96", "2034635 ET INFO Python BaseHTTP ServerBanner: 96", "96", "96"),
        ("Baseline Normal", "96", "2034635 ET INFO Python BaseHTTP ServerBanner: 96", "96", "96"),
        ("Augmented Attack", "174", "2034635: 96; 9103001 ML REVIEW - SYN packet burst: 78", "96", "96"),
        ("Augmented Normal", "174", "2034635: 96; 9103001 ML REVIEW - SYN packet burst: 78", "96", "96"),
    ])
    doc.add_paragraph(
        "All four replays had 96 closed flows with shutdown as the flow reason, and all HTTP events "
        "were GET requests returning status 200. Baseline Suricata therefore did not simply miss all "
        "alerts: it emitted the same informational signature on both scenarios. It did not provide a "
        "scenario-specific attack verdict."
    )
    doc.add_heading("Metrics and rejection", level=2)
    doc.add_paragraph(
        "At whole-PCAP verdict level, baseline and augmented SID evidence are positive on both replay "
        "inputs: TP=1, FP=1, FN=0, TN=0, precision=0.5, recall=1.0, F1=0.667, and false-positive "
        "rate=1.0. This is a two-sample replay comparison, not a valid production classifier benchmark. "
        "The 78/78 SID result is the explicit Normal false-positive rejection gate. Detection-to-rule "
        "effectiveness latency is not reported as a production metric because this candidate was rejected; "
        "the isolated reload itself completed after approximately 22 seconds of engine reload work."
    )

    doc.add_heading("Isolated Suricata 8.0.3 validation", level=1)
    doc.add_paragraph(
        "VM1 used a separate minimal YAML, augmented.rules, output directory, PID file, and UNIX command "
        "socket under /home/tanhv/suricata-rule-review/isolated-vm3-rulegen-v02/. suricata -T with "
        "--init-errors-fatal passed. The isolated daemon started on loopback with af-packet only. "
        "suricatasc returned version 8.0.3 RELEASE and an OK uptime response. ruleset-reload-rules "
        "completed, evidenced by paired detect: rule reload starting and detect: rule reload complete "
        "messages in the isolated log. Only isolated PID 6854 was stopped."
    )
    table(doc, ["Safety check", "Observed result"], [
        ("Production Suricata", "active before and after"),
        ("Production Filebeat", "active before and after"),
        ("Production rule SHA256", "30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b before and after"),
        ("Production reload/restart", "not performed"),
    ])

    doc.add_heading("Limitations and reproducibility", level=1)
    doc.add_paragraph(
        "The paired PCAPs intentionally share SYN volume, destination-port set, handshake completion, "
        "payload direction, and response behavior. A SYN-burst rule cannot separate them. Future work "
        "needs independently collected labels, protocol- or application-aware features, and a held-out "
        "Normal replay before approval. Any Normal replay false positive must reject the candidate."
    )
    doc.add_paragraph(
        "Reproducibility evidence and the exact feature comparison are recorded in "
        "docs/suricata-acceptance-evidence-2026-11-11.md. Private PCAPs, model bundles, credentials, "
        "SSH keys, and runtime outputs are excluded from version control."
    )

    doc.save(OUT)
    print(OUT)


if __name__ == "__main__":
    main()
