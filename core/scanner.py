from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_scan_pdf(scan) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Smartest Bug Hunter Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Target: {scan.target_url}", styles["Heading2"]))
    story.append(Paragraph(f"Status: {scan.status}", styles["BodyText"]))
    story.append(Paragraph(f"Highest severity: {scan.highest_severity}", styles["BodyText"]))
    story.append(Paragraph(f"Total findings: {scan.total_findings}", styles["BodyText"]))
    story.append(Spacer(1, 0.2 * inch))

    data = [["Category", "Severity", "Title", "Evidence"]]
    for finding in scan.findings:
        data.append([
            finding.category,
            finding.severity,
            finding.title,
            finding.evidence[:80] if finding.evidence else "n/a",
        ])

    table = Table(data)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ])
    )
    story.append(table)
    story.append(Spacer(1, 0.2 * inch))

    for finding in scan.findings:
        story.append(Paragraph(f"{finding.title} ({finding.severity})", styles["Heading2"]))
        story.append(Paragraph(f"Category: {finding.category}", styles["BodyText"]))
        story.append(Paragraph(f"Description: {finding.description}", styles["BodyText"]))
        story.append(Paragraph(f"Remediation: {finding.remediation}", styles["BodyText"]))
        story.append(Paragraph(f"Evidence: {finding.evidence or 'n/a'}", styles["BodyText"]))
        story.append(Spacer(1, 0.15 * inch))

    doc.build(story)
    return buffer.getvalue()
