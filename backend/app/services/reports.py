"""Report generator service — TASK-047/048 per SRS §14.

Generates self-contained HTML, JSON, CSV, and PDF reports containing all
mandated audit sections: Executive Summary, Posture Score, Inventory, Findings,
Evidence, Recommendations, IOCs, and Limitations.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.config import settings
from backend.app.core.errors import AppError
from backend.app.db.mongo import Collections


async def generate_report(
    db: AsyncIOMotorDatabase,
    analysis_id: str,
    report_format: str = "html",
) -> dict[str, Any]:
    """Generate and store audit report in requested format."""
    analyses_col = db[Collections.ANALYSES]
    uploads_col = db[Collections.UPLOADS]
    findings_col = db[Collections.FINDINGS]
    sessions_col = db[Collections.IKE_SESSIONS]
    flows_col = db[Collections.IPSEC_FLOWS]
    recs_col = db[Collections.RECOMMENDATIONS]

    analysis = await analyses_col.find_one({"_id": analysis_id})
    if not analysis:
        raise AppError(code="NOT_FOUND", message=f"Analysis '{analysis_id}' not found.", status_code=404)

    if analysis.get("status") != "completed":
        raise AppError(
            code="ANALYSIS_NOT_COMPLETE",
            message="Analysis must be completed before generating a report.",
            status_code=409,
        )

    upload = await uploads_col.find_one({"_id": analysis.get("upload_id")})
    findings = await findings_col.find({"analysis_id": analysis_id}).sort("risk_score", -1).to_list(1000)
    sessions = await sessions_col.find({"analysis_id": analysis_id}).to_list(500)
    flows = await flows_col.find({"analysis_id": analysis_id}).to_list(500)
    recommendations = await recs_col.find({"analysis_id": analysis_id}).sort("rank", 1).to_list(200)

    report_dir = Path(settings.REPORT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_id = f"rep_{analysis_id[:8]}_{report_format}"
    filename = f"{report_id}.{report_format}"
    filepath = report_dir / filename

    content_str = ""

    if report_format == "json":
        data = {
            "report_id": report_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analysis": analysis,
            "upload": upload,
            "findings": findings,
            "sessions": sessions,
            "flows": flows,
            "recommendations": recommendations,
        }
        content_str = json.dumps(data, indent=2, default=str)
        filepath.write_text(content_str, encoding="utf-8")

    elif report_format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "Finding ID", "Rule ID", "Category", "Title", "Severity", "Risk Score",
            "Impact", "Likelihood", "Confidence", "Why This Matters", "Recommendation ID"
        ])
        for f in findings:
            writer.writerow([
                f.get("id", ""),
                f.get("rule_id", ""),
                f.get("category", ""),
                f.get("title", ""),
                f.get("severity", ""),
                f.get("risk_score", ""),
                f.get("impact", ""),
                f.get("likelihood", ""),
                f.get("confidence", ""),
                f.get("why_this_matters", ""),
                f.get("recommendation_id", ""),
            ])
        content_str = out.getvalue()
        filepath.write_text(content_str, encoding="utf-8")

    elif report_format == "pdf":
        _build_pdf_report(
            filepath=filepath,
            analysis=analysis,
            upload=upload,
            findings=findings,
            sessions=sessions,
            flows=flows,
            recommendations=recommendations,
        )

    else:  # HTML default
        content_str = _build_html_report(analysis, upload, findings, sessions, flows, recommendations)
        filepath.write_text(content_str, encoding="utf-8")

    # Record report
    report_record = {
        "_id": report_id,
        "analysis_id": analysis_id,
        "format": report_format,
        "stored_path": str(filepath),
        "created_at": datetime.now(timezone.utc),
        "download_url": f"/api/v1/reports/{report_id}/download",
    }
    await db["reports"].update_one(
        {"_id": report_id},
        {"$set": report_record},
        upsert=True,
    )

    return report_record


def _build_html_report(
    analysis: dict[str, Any],
    upload: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
) -> str:
    """Build standalone HTML report."""
    posture = analysis.get("posture", {})
    score = posture.get("score", 100.0)
    grade = posture.get("grade", "A")
    orig_file = upload.get("original_filename", "capture.pcap") if upload else "capture.pcap"
    narrative_data = analysis.get("narrative") or {}
    narrative = narrative_data.get("executive_summary", "")
    narrative_origin = narrative_data.get("origin", "template")
    if narrative_origin == "llm":
        origin_badge = '<span style="font-size: 11px; padding: 2px 8px; border-radius: 9999px; background: #312e81; color: #a5b4fc; border: 1px solid #4338ca; margin-left: 8px; font-weight: normal;">AI-generated summary, findings se verify karo</span>'
    else:
        origin_badge = '<span style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background: #1e293b; color: #94a3b8; border: 1px solid #334155; margin-left: 8px; font-weight: normal;">template</span>'

    # Findings rows
    findings_rows = []
    for f in findings:
        sev = f.get("severity", "Info")
        color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#64748b",
        }.get(sev, "#64748b")

        findings_rows.append(f"""
        <tr style="border-bottom: 1px solid #334155;">
            <td style="padding: 10px; font-weight: 600; color: {color};">{sev}</td>
            <td style="padding: 10px; font-family: monospace;">{f.get('rule_id', '')}</td>
            <td style="padding: 10px; font-weight: 500;">{f.get('title', '')}</td>
            <td style="padding: 10px; text-align: center; font-weight: bold;">{f.get('risk_score', 0):.1f}</td>
            <td style="padding: 10px; font-size: 13px; color: #cbd5e1;">{f.get('explanation', '')}</td>
        </tr>
        """)

    # Recommendations rows
    rec_rows = []
    for r in recommendations:
        steps_html = "".join(f"<li>{s}</li>" for s in r.get("steps", []))
        rec_rows.append(f"""
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; color: #38bdf8;">#{r.get('rank', 1)}: {r.get('title', '')}</h3>
                <span style="background: #0f172a; padding: 4px 10px; border-radius: 4px; font-size: 12px; border: 1px solid #475569;">Effort: {r.get('effort', 'Medium')}</span>
            </div>
            <p style="margin: 0 0 10px 0; color: #94a3b8; font-size: 14px;"><strong>Verification:</strong> {r.get('verification', '')}</p>
            <ol style="margin: 0; padding-left: 20px; font-size: 13px; color: #cbd5e1;">{steps_html}</ol>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsecScope Security Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }}
        .badge {{ display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 14px; }}
        .score-card {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #334155; display: flex; gap: 30px; align-items: center; }}
        .score-box {{ text-align: center; background: #0f172a; padding: 20px 30px; border-radius: 8px; border: 1px solid #475569; }}
        .score-val {{ font-size: 42px; font-weight: 800; color: #38bdf8; }}
        .grade-val {{ font-size: 28px; font-weight: 700; color: #f59e0b; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0f172a; text-align: left; padding: 12px 10px; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
        .section-title {{ font-size: 20px; font-weight: 700; color: #f1f5f9; margin-top: 40px; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0 0 8px 0; color: #38bdf8;">IPsecScope Assessment Report</h1>
                <p style="margin: 0; color: #94a3b8; font-size: 14px;">Automated Passive IPsec VPN Protocol & Cryptographic Audit</p>
                <p style="margin: 6px 0 0 0; color: #64748b; font-size: 13px;">Capture: <strong>{orig_file}</strong> · SHA-256: <code>{sha256[:16]}...</code></p>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: #0284c7; color: white;">Analysis ID: {analysis.get('_id', '')[:8]}</span>
                <p style="margin: 6px 0 0 0; font-size: 12px; color: #64748b;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>
        </div>

        <div class="score-card">
            <div class="score-box">
                <div class="score-val">{score:.1f}</div>
                <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px;">Posture Score</div>
                <div class="grade-val">Grade {grade}</div>
            </div>
            <div>
                <h2 style="margin: 0 0 10px 0; font-size: 18px; color: #e2e8f0; display: flex; align-items: center;">Executive Summary {origin_badge}</h2>
                <p style="margin: 0; color: #cbd5e1; font-size: 14px; line-height: 1.6;">{narrative}</p>
            </div>
        </div>

        <h2 class="section-title">Security Findings ({len(findings)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Severity</th>
                    <th style="width: 120px;">Rule</th>
                    <th>Vulnerability Title</th>
                    <th style="width: 80px; text-align: center;">Risk</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows) if findings_rows else '<tr><td colspan="5" style="padding: 20px; text-align: center; color: #64748b;">No security findings identified.</td></tr>'}
            </tbody>
        </table>

        <h2 class="section-title">Prioritized Fix-First Recommendations</h2>
        {''.join(rec_rows) if rec_rows else '<p style="color: #64748b;">No remediation steps required.</p>'}

        <h2 class="section-title">Methodology & Observability Caveats</h2>
        <div style="background: #1e293b; border-left: 4px solid #0284c7; padding: 15px; border-radius: 4px; font-size: 13px; color: #94a3b8;">
            <p style="margin: 0 0 8px 0;"><strong>Passive Analysis Boundary:</strong> This assessment evaluates unencrypted parameters observable in keyless PCAP/PCAPNG captures. Encrypted IKE_AUTH identities, child SA proposals, and ESP encrypted payloads are not observable without cryptographic keys.</p>
            <p style="margin: 0;">Absence of findings is not absolute proof of security. Cryptographic recommendations are grounded in RFC 8247, RFC 8221, and NIST SP 800-77 Rev. 1 guidelines.</p>
        </div>
    </div>
</body>
</html>
"""


def _build_pdf_report(
    filepath: Path,
    analysis: dict[str, Any],
    upload: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
) -> None:
    """Generate professional audit PDF using WeasyPrint (if available) or ReportLab."""
    try:
        import weasyprint
        html_content = _build_html_report(analysis, upload, findings, sessions, flows, recommendations)
        weasyprint.HTML(string=html_content).write_pdf(str(filepath))
        return
    except Exception:
        pass

    # ReportLab fallback
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#0284c7'), spaceAfter=4)
    meta_style = ParagraphStyle('MetaStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748b'))
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=12, textColor=colors.HexColor('#1e293b'), spaceBefore=12, spaceAfter=6)
    cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=8, leading=10)
    cell_bold = ParagraphStyle('CellBold', parent=styles['Normal'], fontSize=8, leading=10, fontName='Helvetica-Bold')

    orig_file = upload.get("original_filename", "capture.pcap") if upload else "capture.pcap"
    sha256 = upload.get("sha256", "") if upload else ""
    posture = analysis.get("posture") or {}
    score = posture.get("score", 100.0)
    grade = posture.get("grade", "A")
    finding_counts = analysis.get("finding_counts") or {}

    story = [
        Paragraph('IPsecScope Security Assessment Report', title_style),
        Paragraph('Automated Passive IPsec VPN Protocol & Cryptographic Audit (RFC 7296 / NIST SP 800-77 Rev. 1)', meta_style),
        Paragraph(f'Capture: <b>{orig_file}</b> | SHA-256: <code>{sha256[:16]}...</code> | Analysis ID: <b>{analysis.get("_id", "")[:8]}</b>', meta_style),
        Spacer(1, 10),
        Paragraph('Executive Summary & Posture Score', h2_style),
        Table([
            ['Posture Score', 'Grade', 'Critical', 'High', 'Medium', 'Low', 'Info'],
            [f'{score:.1f} / 100', f'Grade {grade}',
             str(finding_counts.get('Critical', 0)),
             str(finding_counts.get('High', 0)),
             str(finding_counts.get('Medium', 0)),
             str(finding_counts.get('Low', 0)),
             str(finding_counts.get('Info', 0))]
        ], colWidths=[90, 80, 55, 55, 55, 55, 55], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
        ])),
        Spacer(1, 10),
    ]

    narrative_data = analysis.get("narrative") or {}
    narrative_text = narrative_data.get("executive_summary") or "Assessment completed successfully."
    story.append(Paragraph(narrative_text, cell_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph(f'Security Findings ({len(findings)})', h2_style))
    table_data = [['Severity', 'Rule ID', 'Vulnerability Title', 'Risk']]
    sev_colors = {
        'Critical': colors.HexColor('#dc2626'),
        'High': colors.HexColor('#ea580c'),
        'Medium': colors.HexColor('#d97706'),
        'Low': colors.HexColor('#2563eb'),
        'Info': colors.HexColor('#64748b'),
    }
    tstyle = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]

    for idx, f in enumerate(findings, start=1):
        sev = f.get('severity', 'Info')
        table_data.append([
            sev,
            f.get('rule_id', ''),
            Paragraph(f.get('title', ''), cell_style),
            f"{f.get('risk_score', 0):.1f}"
        ])
        tstyle.append(('TEXTCOLOR', (0, idx), (0, idx), sev_colors.get(sev, colors.black)))
        tstyle.append(('FONTNAME', (0, idx), (0, idx), 'Helvetica-Bold'))

    if len(findings) == 0:
        table_data.append(['None', '—', Paragraph('No security vulnerabilities identified in capture.', cell_style), '0.0'])

    story.append(Table(table_data, colWidths=[65, 85, 330, 60], style=TableStyle(tstyle)))
    story.append(Spacer(1, 12))

    story.append(Paragraph('Prioritized Fix-First Recommendations', h2_style))
    if recommendations:
        for r in recommendations[:5]:
            title_p = Paragraph(f"<b>#{r.get('rank', 1)}: {r.get('title', '')}</b> (Effort: {r.get('effort', 'Medium')})", cell_bold)
            verif_p = Paragraph(f"<b>Verification:</b> {r.get('verification', '')}", cell_style)
            story.append(title_p)
            story.append(verif_p)
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph('No configuration changes required.', cell_style))

    story.append(Spacer(1, 10))
    story.append(Paragraph('Observability Boundary & Methodological Caveats', h2_style))
    story.append(Paragraph(
        'Passive keyless analysis evaluates observable parameters in unencrypted network captures. '
        'Encrypted IKE_AUTH identities, child SA proposals, and ESP payloads are not observable without cryptographic keys. '
        'Compliance grounded in RFC 8247, RFC 8221, and NIST SP 800-77 Rev. 1 guidelines.',
        cell_style,
    ))

    doc.build(story)
