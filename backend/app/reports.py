from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def create_report(analysis: dict[str, Any]) -> bytes:
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    capture = analysis["capture"]
    assessment = analysis["assessment"]
    elements = [
        Paragraph("HACKGRID — IPsec VPN Security Analyzer", styles["Title"]),
        Paragraph("SIH 2026 · SIH26160 · Technical analysis report", styles["Normal"]),
        Spacer(1, 14),
    ]
    summary = [
        ["Analysis ID", analysis["id"]],
        ["Input", analysis["filename"] + (" (SYNTHETIC DEMO DATA)" if analysis["demo"] else "")],
        ["Analysis time (UTC)", analysis["created_at"]],
        ["Packets processed", str(capture["packet_count"])],
        ["IKE / ESP / AH", f'{capture["ike_count"]} / {capture["esp_count"]} / {capture["ah_count"]}'],
        ["Risk score", f'{assessment["score"]}/100 — {assessment["category"]}'],
    ]
    elements.append(Table(summary, colWidths=[145, 365], style=TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f8")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 7),
    ])))
    elements.extend([Spacer(1, 16), Paragraph("Observed IKEv2 transforms (offered, not negotiated)", styles["Heading2"])])
    transforms = capture["transforms"]
    elements.append(Paragraph(", ".join(sorted({item["name"] for item in transforms})) if transforms else "None observed", styles["BodyText"]))
    elements.extend([Spacer(1, 12), Paragraph("Security assessment", styles["Heading2"])])
    rows = [["Parameter", "Observed", "Status", "Reason"]]
    for finding in assessment["findings"]:
        rows.append([
            Paragraph(finding["parameter"], styles["BodyText"]),
            Paragraph(finding["observed"], styles["BodyText"]),
            finding["status"],
            Paragraph(finding["reason"], styles["BodyText"]),
        ])
    table = Table(rows, colWidths=[88, 100, 54, 268], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102238")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.extend([table, Spacer(1, 14), Paragraph("Limitations", styles["Heading2"])])
    limitations = (
        "This report covers offline classic PCAP v2.4 (Ethernet or raw IP) only. PCAPNG, live capture, "
        "ESP decryption, ML classification, blockchain, and PostgreSQL are not implemented. "
        "Security rules are a small demonstrator policy, not a compliance certification. "
        "IKEv2 transforms are reported as offered; a proposal is not evidence of negotiated settings. "
        "UNKNOWN means the capture does not expose that setting."
    )
    elements.append(Paragraph(limitations, styles["BodyText"]))
    doc.build(elements)
    return output.getvalue()
