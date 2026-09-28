"""
PDF report generator for CyberForensX cases.

Produces a concise report with case metadata, artifact summary, and alerts.
The database layer returns sqlite3.Row objects, so this module uses mapping
access for every database record.
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database.db_setup import get_alerts_for_case, get_artifacts_for_case, get_case


def _row_value(row, key: str, default: str = "") -> str:
    if row is None:
        return default
    try:
        return row[key] if row[key] is not None else default
    except Exception:
        return getattr(row, key, default)


def generate_case_pdf(case_id: str, report_type: str = "technical", out_dir: str = None) -> str:
    """Generate a PDF report for a case and return the file path."""
    if out_dir is None:
        out_dir = os.path.join(os.getcwd(), "storage", "processed")
    os.makedirs(out_dir, exist_ok=True)

    case = get_case(case_id)
    if not case:
        raise FileNotFoundError(f"Case not found: {case_id}")

    filename = f"{case_id}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = os.path.join(out_dir, filename)

    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "CyberForensXBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=10.5,
        wordWrap="CJK",
    )
    cell_style = ParagraphStyle(
        "CyberForensXCell",
        parent=body_style,
        fontSize=7.4,
        leading=8.6,
    )

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=28,
        rightMargin=28,
        topMargin=32,
        bottomMargin=28,
    )
    flow = []

    title_text = f"CyberForensX {report_type.capitalize()} Case Report: {case_id}"
    if report_type == "executive":
        title_text = f"CyberForensX Executive Summary: {case_id}"
        
    flow.append(Paragraph(title_text, styles["Title"]))
    flow.append(Spacer(1, 10))
    flow.append(
        Paragraph(
            f"Title: {_row_value(case, 'title')}<br/>"
            f"Investigator: {_row_value(case, 'investigator')}<br/>"
            f"Status: {_row_value(case, 'status', 'unknown')}<br/>"
            f"Created: {_row_value(case, 'created_at')}",
            styles["Normal"],
        )
    )
    flow.append(Spacer(1, 14))

    alerts = get_alerts_for_case(case_id)
    
    if report_type == "executive":
        risk_score = 0
        high = medium = low = 0
        for alert in alerts:
            sev = _row_value(alert, "severity").lower()
            if sev == "high": 
                risk_score += 10
                high += 1
            elif sev == "medium": 
                risk_score += 5
                medium += 1
            else: 
                risk_score += 1
                low += 1
        
        flow.append(Paragraph(f"Executive Risk Impact Summary", styles["Heading2"]))
        flow.append(Paragraph(
            f"<b>Overall System Risk Score:</b> {risk_score} <br/>"
            f"<b>Critical / High Alerts:</b> {high} <br/>"
            f"<b>Suspicious / Medium Alerts:</b> {medium} <br/>"
            f"<b>Informational / Low Alerts:</b> {low} <br/><br/>"
            f"<i>This executive report summarizes overarching security risks without detailed forensic extraction metrics.</i>",
            styles["Normal"]
        ))
        flow.append(Spacer(1, 14))
        
    flow.append(Paragraph(f"Alerts ({len(alerts)})", styles["Heading2"]))
    if alerts:
        alert_rows = [["#", "Type", "Severity", "Detected At", "Description"]]
        for idx, alert in enumerate(alerts, 1):
            alert_rows.append([
                Paragraph(str(idx), cell_style),
                Paragraph(_row_value(alert, "alert_type") or "—", cell_style),
                Paragraph(_row_value(alert, "severity") or "—", cell_style),
                Paragraph(_row_value(alert, "detected_at") or "—", cell_style),
                Paragraph(_row_value(alert, "description")[:220] or "—", cell_style),
            ])
        alert_table = Table(alert_rows, colWidths=[24, 84, 58, 86, 260], repeatRows=1)
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEADING", (0, 0), (-1, -1), 8.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        flow.append(alert_table)
    else:
        flow.append(Paragraph("No alerts recorded.", styles["Normal"]))

    flow.append(Spacer(1, 14))

    artifacts = get_artifacts_for_case(case_id)
    flow.append(Paragraph(f"Artifacts ({len(artifacts)})", styles["Heading2"]))
    
    if report_type == "executive":
        flow.append(Paragraph(f"{len(artifacts)} digital artifacts isolated and secured in chain of custody. Omitted raw hash details in executive view.", styles["Normal"]))
    elif artifacts:
        artifact_rows = [["#", "Name", "Type", "SHA256"]]
        for idx, art in enumerate(artifacts, 1):
            sha256 = _row_value(art, "sha256_hash") or ""
            if len(sha256) > 22:
                sha256 = f"{sha256[:10]}…{sha256[-10:]}"
            artifact_rows.append([
                Paragraph(str(idx), cell_style),
                Paragraph(_row_value(art, "artifact_name") or "—", cell_style),
                Paragraph(_row_value(art, "artifact_type") or "—", cell_style),
                Paragraph(sha256 or "—", cell_style),
            ])
        artifact_table = Table(artifact_rows, colWidths=[24, 178, 82, 228], repeatRows=1)
        artifact_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEADING", (0, 0), (-1, -1), 8.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        flow.append(artifact_table)
    else:
        flow.append(Paragraph("No artifacts recorded.", styles["Normal"]))

    flow.append(Spacer(1, 16))
    flow.append(Paragraph(f"Generated at {datetime.now().isoformat()}", styles["Italic"]))

    doc.build(flow)
    return out_path
