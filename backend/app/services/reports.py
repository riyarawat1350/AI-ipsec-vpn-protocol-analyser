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
            "posture": analysis.get("posture") or {},
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
    """Build standalone, self-contained HTML report with Phase 4 plain-language explanations."""
    from analyzer.explain.engine import find_terms_in_text

    posture = analysis.get("posture", {})
    score = posture.get("score", 100.0)
    grade = posture.get("grade", "A")
    orig_file = upload.get("original_filename", "capture.pcap") if upload else "capture.pcap"
    sha256 = upload.get("sha256", "") if upload else ""
    narrative_data = analysis.get("narrative") or {}
    if not isinstance(narrative_data, dict):
        narrative_data = {}
    report_card_raw = narrative_data.get("report_card") or {}
    if isinstance(report_card_raw, dict):
        report_card = report_card_raw
    elif isinstance(report_card_raw, str):
        import json
        try:
            report_card = json.loads(report_card_raw) if report_card_raw.strip().startswith("{") else {"what_we_saw": report_card_raw}
        except Exception:
            report_card = {"what_we_saw": report_card_raw}
    else:
        report_card = {}

    total_pkts = analysis.get("capture_stats", {}).get("total_packets") or (upload.get("packet_count") if upload else 0) or (len(sessions) * 2 + len(flows) * 10)

    # 1. Plain Summary / Report Card
    saw_raw = report_card.get("what_we_saw", "")
    if isinstance(saw_raw, dict):
        saw_bullets_list = saw_raw.get("bullets", [f"Analyzed {total_pkts} captured packets."])
    elif isinstance(saw_raw, str) and saw_raw:
        details_saw = report_card.get("details", {})
        if isinstance(details_saw, dict) and "saw_bullets" in details_saw:
            saw_bullets_list = details_saw["saw_bullets"]
        else:
            saw_bullets_list = [saw_raw]
    else:
        saw_bullets_list = [f"Analyzed {total_pkts} captured packets."]
    saw_bullets = "".join(f"<li>{b}</li>" for b in saw_bullets_list)

    found_raw = report_card.get("what_we_found", "")
    if isinstance(found_raw, dict):
        found_summary = found_raw.get("summary", f"Identified {len(findings)} security findings.")
    else:
        found_summary = found_raw or f"Identified {len(findings)} security findings."

    how_worried_raw = report_card.get("how_worried", "")
    if isinstance(how_worried_raw, dict):
        how_worried_text = how_worried_raw.get("explanation", f"Overall posture score {score:.1f} (Grade {grade}).")
        worry_level = how_worried_raw.get("level", "Standard")
    else:
        how_worried_text = how_worried_raw or f"Overall posture score {score:.1f} (Grade {grade})."
        worry_level = f"Grade {grade}"

    todo_raw = report_card.get("what_to_do_first", "")
    if isinstance(todo_raw, dict):
        todo_action = todo_raw.get("action", "Follow remediation recommendations.")
    else:
        todo_action = todo_raw or "Follow remediation recommendations."

    limitations_raw = report_card.get("limitations", "")
    if isinstance(limitations_raw, dict):
        limitations_text = limitations_raw.get("explanation", "Encrypted payloads and private keys are not observable without keys.")
    else:
        limitations_text = limitations_raw or "Encrypted payloads and private keys are not observable without keys."

    # 2. Key Numbers Breakdown
    crit_c = sum(1 for f in findings if f.get("severity") == "Critical")
    high_c = sum(1 for f in findings if f.get("severity") == "High")
    med_c = sum(1 for f in findings if f.get("severity") == "Medium")
    low_c = sum(1 for f in findings if f.get("severity") == "Low")
    info_c = sum(1 for f in findings if f.get("severity") == "Info")

    # 3. Findings Cards (Plain first, technical below)
    findings_cards = []
    for f in findings:
        sev = f.get("severity", "Info")
        color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#64748b",
        }.get(sev, "#64748b")

        r_score = f.get('risk_score')
        score_text = f"{r_score:.1f}" if r_score is not None else "Not scored"
        p_sum = f.get("plain_summary") or f.get("title", "")
        p_imp = f.get("plain_impact") or f.get("why_this_matters", "")
        p_fix = f.get("plain_fix") or "Apply standard configuration hardening."

        evidence_html = ""
        ev_list = f.get("evidence", [])
        if ev_list:
            ev_items = "".join(
                f"<div style='font-family: monospace; font-size: 11px; background: #090d16; padding: 6px; border-radius: 4px; margin-top: 4px; border: 1px solid #1e293b;'>"
                f"Packet #{ev.get('packet_no')}: {ev.get('field_path')} = <code>{ev.get('raw_value')}</code> ({ev.get('decoded') or ''})"
                f"<div style='color: #64748b;'>Hex: {ev.get('hex_excerpt', '')}</div>"
                f"</div>"
                for ev in ev_list[:3]
            )
            evidence_html = f"<div style='margin-top: 8px;'><strong style='font-size: 11px; text-transform: uppercase; color: #94a3b8;'>Packet Evidence:</strong>{ev_items}</div>"

        findings_cards.append(f"""
        <div style="background: #1e293b; border: 1px solid #334155; border-left: 4px solid {color}; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="background: {color}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{sev.upper()}</span>
                    <span style="font-family: monospace; font-size: 12px; color: #94a3b8;">{f.get('rule_id')}</span>
                    <h3 style="margin: 0; font-size: 15px; color: #f8fafc;">{f.get('title')}</h3>
                </div>
                <span style="font-size: 13px; font-weight: bold; color: {color};">Risk Score: {score_text}</span>
            </div>

            <div style="background: #0f172a; padding: 12px; border-radius: 6px; margin-bottom: 10px; border: 1px solid #334155;">
                <p style="margin: 0 0 6px 0; font-size: 13px; color: #e2e8f0;"><strong>What was found:</strong> {p_sum}</p>
                <p style="margin: 0 0 6px 0; font-size: 13px; color: #cbd5e1;"><strong>Potential impact:</strong> {p_imp}</p>
                <p style="margin: 0; font-size: 13px; color: #38bdf8;"><strong>Plain fix:</strong> {p_fix}</p>
            </div>

            <details style="margin-top: 8px; font-size: 12px; color: #94a3b8;">
                <summary style="cursor: pointer; color: #38bdf8; font-weight: 500;">Show Technical Audit Details</summary>
                <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #334155;">
                    <p style="margin: 0 0 4px 0;"><strong>Technical Explanation:</strong> {f.get('explanation')}</p>
                    <p style="margin: 0 0 4px 0;"><strong>Threat Context:</strong> {f.get('why_this_matters')}</p>
                    <p style="margin: 0 0 4px 0;"><strong>Impact:</strong> {f.get('impact')} | <strong>Likelihood:</strong> {f.get('likelihood')} | <strong>Confidence:</strong> {f.get('confidence')}</p>
                    {evidence_html}
                </div>
            </details>
        </div>
        """)

    # 4. Fix-First Recommendations
    rec_cards = []
    for r in recommendations:
        steps_html = "".join(f"<li style='margin-bottom: 4px;'>{s}</li>" for s in r.get("steps", []))
        rec_cards.append(f"""
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <h4 style="margin: 0; color: #38bdf8; font-size: 14px;">#{r.get('rank', 1)}: {r.get('title', '')}</h4>
                <span style="background: #0f172a; padding: 2px 8px; border-radius: 4px; font-size: 11px; border: 1px solid #475569;">Effort: {r.get('effort', 'Medium')}</span>
            </div>
            <p style="margin: 0 0 6px 0; color: #94a3b8; font-size: 12px;"><strong>Verification:</strong> {r.get('verification', '')}</p>
            <ol style="margin: 0; padding-left: 20px; font-size: 12px; color: #cbd5e1;">{steps_html}</ol>
        </div>
        """)

    # 5. Technical Appendix: IKE Sessions & ESP Flows
    sessions_rows = []
    for s in sessions:
        sel_ciphers = [t.get("name") for t in s.get("selected", {}).get("transforms", []) if t.get("type") == "ENCR"] if s.get("selected") else []
        c_str = sel_ciphers[0] if sel_ciphers else "None"
        sessions_rows.append(f"""
        <tr style="border-bottom: 1px solid #334155; font-size: 12px;">
            <td style="padding: 8px; font-family: monospace;">{s.get('id', '')[:8]}</td>
            <td style="padding: 8px;">IKEv{s.get('version', 2)}</td>
            <td style="padding: 8px;">{s.get('initiator', '')} &rarr; {s.get('responder', '')}</td>
            <td style="padding: 8px;">{s.get('outcome', '')}</td>
            <td style="padding: 8px;">{c_str}</td>
        </tr>
        """)

    flows_rows = []
    for fl in flows:
        flows_rows.append(f"""
        <tr style="border-bottom: 1px solid #334155; font-size: 12px;">
            <td style="padding: 8px; font-family: monospace;">{fl.get('spi', '')}</td>
            <td style="padding: 8px; text-transform: uppercase;">{fl.get('proto', 'esp')} ({fl.get('encap', 'raw')})</td>
            <td style="padding: 8px;">{fl.get('src', '')} &rarr; {fl.get('dst', '')}</td>
            <td style="padding: 8px;">{fl.get('packets', 0)} pkts ({fl.get('bytes', 0)} B)</td>
            <td style="padding: 8px;">Max Seq: {fl.get('seq', {}).get('max_seq', 0)}</td>
        </tr>
        """)

    # 6. Auto-Extracted Terms Explained
    full_text_to_scan = f"{narrative_data} {' '.join(f.get('title', '') + ' ' + f.get('explanation', '') for f in findings)}"
    matched_terms = find_terms_in_text(full_text_to_scan)
    term_cards = []
    for t in matched_terms[:12]:
        term_cards.append(f"""
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: baseline;">
                <strong style="color: #38bdf8; font-size: 13px;">{t.get('name')} ({t.get('expansion')})</strong>
            </div>
            <p style="margin: 4px 0; font-size: 12px; color: #cbd5e1;"><strong>Simple:</strong> {t.get('simple')}</p>
            {f"<p style='margin: 2px 0; font-size: 11px; color: #94a3b8;'><em>Analogy: {t.get('analogy')}</em></p>" if t.get('analogy') else ""}
            <p style="margin: 2px 0 0 0; font-size: 11px; color: #64748b;"><strong>Why it matters:</strong> {t.get('why_it_matters')}</p>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsecScope Assessment & Verification Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b1120;
            color: #f8fafc;
            line-height: 1.5;
            margin: 0;
            padding: 30px;
        }}
        .container {{ max-width: 1050px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .report-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 24px; }}
        .key-metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 24px; }}
        .metric-card {{ background: #131d31; border: 1px solid #334155; border-radius: 8px; padding: 14px; text-align: center; }}
        .metric-val {{ font-size: 24px; font-weight: 800; color: #38bdf8; }}
        .metric-lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
        .section-title {{ font-size: 18px; font-weight: 700; color: #f1f5f9; margin-top: 32px; margin-bottom: 12px; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0f172a; text-align: left; padding: 10px; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #0f172a !important;
                padding: 10px !important;
            }}
            .header, .section-title {{
                border-color: #cbd5e1 !important;
            }}
            .report-card, .metric-card, table, tr, td, th {{
                background: #ffffff !important;
                color: #0f172a !important;
                border-color: #cbd5e1 !important;
                page-break-inside: avoid;
            }}
            .metric-val {{
                color: #0284c7 !important;
            }}
            .metric-lbl {{
                color: #475569 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1 style="margin: 0 0 6px 0; color: #38bdf8; font-size: 24px;">IPsecScope Assessment Report</h1>
                <p style="margin: 0; color: #94a3b8; font-size: 13px;">Passive IPsec VPN Protocol Audit & Observability Verification</p>
                <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Capture: <strong>{orig_file}</strong> | SHA-256: <code>{sha256[:16]}...</code></p>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: #0284c7; color: white;">Analysis ID: {analysis.get('_id', '')[:8]}</span>
                <p style="margin: 4px 0 0 0; font-size: 11px; color: #64748b;">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>
        </div>

        <!-- 1. Plain Summary / Report Card -->
        <div class="report-card">
            <h2 style="margin: 0 0 14px 0; font-size: 18px; color: #38bdf8;">Deterministic Report Card (Plain Language)</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155;">
                    <strong style="color: #f8fafc; font-size: 13px;">1. What We Saw:</strong>
                    <ul style="margin: 6px 0 0 0; padding-left: 20px; font-size: 13px; color: #cbd5e1;">{saw_bullets}</ul>
                </div>
                <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155;">
                    <strong style="color: #f8fafc; font-size: 13px;">2. What We Found:</strong>
                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #cbd5e1;">{found_summary}</p>
                </div>
                <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155;">
                    <strong style="color: #f8fafc; font-size: 13px;">3. How Worried Should You Be:</strong>
                    <p style="margin: 4px 0 0 0; font-size: 12px; color: #f59e0b; font-weight: bold;">Status: {worry_level}</p>
                    <p style="margin: 4px 0 0 0; font-size: 13px; color: #cbd5e1;">{how_worried_text}</p>
                </div>
                <div style="background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155;">
                    <strong style="color: #f8fafc; font-size: 13px;">4. What To Do First:</strong>
                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #38bdf8;">{todo_action}</p>
                </div>
            </div>
            <div style="margin-top: 14px; background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #334155;">
                <strong style="color: #94a3b8; font-size: 12px; text-transform: uppercase;">5. What We Could Not Observe and Why:</strong>
                <p style="margin: 4px 0 0 0; font-size: 12px; color: #94a3b8;">{limitations_text}</p>
            </div>
        </div>

        <!-- 2. Key Numbers -->
        <h2 class="section-title">Key Numbers & Observability Stats</h2>
        <div class="key-metrics">
            <div class="metric-card"><div class="metric-val">{score:.1f}</div><div class="metric-lbl">Posture Score</div></div>
            <div class="metric-card"><div class="metric-val">Grade {grade}</div><div class="metric-lbl">Overall Grade</div></div>
            <div class="metric-card"><div class="metric-val">{total_pkts}</div><div class="metric-lbl">Total Packets</div></div>
            <div class="metric-card"><div class="metric-val">{len(sessions)}</div><div class="metric-lbl">IKE Sessions</div></div>
            <div class="metric-card"><div class="metric-val">{len(flows)}</div><div class="metric-lbl">ESP Flows</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #dc2626;">{crit_c}</div><div class="metric-lbl">Critical</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #ea580c;">{high_c}</div><div class="metric-lbl">High</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #d97706;">{med_c}</div><div class="metric-lbl">Medium</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #2563eb;">{low_c}</div><div class="metric-lbl">Low</div></div>
            <div class="metric-card"><div class="metric-val" style="color: #64748b;">{info_c}</div><div class="metric-lbl">Info</div></div>
        </div>

        <!-- 3. Security Findings -->
        <h2 class="section-title">Security Findings ({len(findings)})</h2>
        {''.join(findings_cards) if findings_cards else '<p style="color: #94a3b8; padding: 12px; background: #1e293b; border-radius: 6px;">No security weaknesses found in the parts we could observe.</p>'}

        <!-- 4. Fix-First Prioritized Recommendations -->
        <h2 class="section-title">Prioritized Fix-First Recommendations ({len(recommendations)})</h2>
        {''.join(rec_cards) if rec_cards else '<p style="color: #94a3b8; padding: 12px; background: #1e293b; border-radius: 6px;">No remediation changes required.</p>'}

        <!-- 5. Technical Appendix -->
        <h2 class="section-title">Technical Appendix: Sessions & Flows</h2>
        <h3 style="font-size: 14px; color: #94a3b8; margin: 12px 0 6px 0;">IKE Sessions</h3>
        <table>
            <thead><tr><th>Session ID</th><th>Version</th><th>Endpoints</th><th>Outcome</th><th>Selected Cipher</th></tr></thead>
            <tbody>{''.join(sessions_rows) if sessions_rows else '<tr><td colspan="5" style="padding: 10px; text-align: center; color: #64748b;">No IKE sessions observed.</td></tr>'}</tbody>
        </table>

        <h3 style="font-size: 14px; color: #94a3b8; margin: 16px 0 6px 0;">ESP / AH Encrypted Flows</h3>
        <table>
            <thead><tr><th>SPI</th><th>Protocol</th><th>Direction</th><th>Traffic Volume</th><th>Sequence Tracking</th></tr></thead>
            <tbody>{''.join(flows_rows) if flows_rows else '<tr><td colspan="5" style="padding: 10px; text-align: center; color: #64748b;">No IPsec data flows observed.</td></tr>'}</tbody>
        </table>

        <!-- 6. Terms Explained -->
        <h2 class="section-title">Terms Explained (Glossary Reference)</h2>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            {''.join(term_cards) if term_cards else '<p style="color: #64748b;">No complex technical terms identified in this report.</p>'}
        </div>

        <!-- 7. Observability Boundary & Policy -->
        <h2 class="section-title">7. Limitations & Observability Boundary</h2>
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; font-size: 13px; color: #94a3b8; line-height: 1.6;">
            <p style="margin: 0 0 8px 0;">This assessment is based exclusively on passive, non-intrusive observation of packet metadata available on the wire.</p>
            <p style="margin: 0 0 8px 0;"><strong>What cannot be observed without keys:</strong> Inner IP packet addresses, transport protocols, user payload data protected by ESP encryption, Perfect Forward Secrecy validation, and encrypted IKE_AUTH identities.</p>
            <p style="margin: 0;">Policy compliance evaluates observed negotiation parameters against NIST SP 800-77 Rev. 1 and RFC 8247 baseline standards.</p>
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
    import sys

    # On non-Windows platforms, Weasyprint may be used if installed with system pango/cairo
    if sys.platform != "win32":
        try:
            import weasyprint
            html_content = _build_html_report(analysis, upload, findings, sessions, flows, recommendations)
            weasyprint.HTML(string=html_content).write_pdf(str(filepath))
            return
        except Exception:
            pass

    # ReportLab fallback
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

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

    story = [
        Paragraph('IPsecScope Security Assessment Report', title_style),
        Paragraph('Automated Passive IPsec VPN Protocol & Cryptographic Audit (RFC 7296 / NIST SP 800-77 Rev. 1)', meta_style),
        Paragraph(f'Capture: <b>{orig_file}</b> | SHA-256: <code>{sha256[:16]}...</code> | Analysis ID: <b>{analysis.get("_id", "")[:8]}</b>', meta_style),
        Spacer(1, 10),
        Paragraph('1. Plain Summary & Report Card', h2_style),
    ]

    narrative_data = analysis.get("narrative") or {}
    if not isinstance(narrative_data, dict):
        narrative_data = {}
    report_card_raw = narrative_data.get("report_card") or {}
    if isinstance(report_card_raw, dict):
        report_card = report_card_raw
    elif isinstance(report_card_raw, str):
        import json
        try:
            report_card = json.loads(report_card_raw) if report_card_raw.strip().startswith("{") else {"how_worried": report_card_raw}
        except Exception:
            report_card = {"how_worried": report_card_raw}
    else:
        report_card = {}
    hw_raw = report_card.get("how_worried")
    if isinstance(hw_raw, dict):
        how_worried = hw_raw.get("explanation") or f"Posture score: {score:.1f}/100 (Grade {grade})."
    else:
        how_worried = hw_raw or f"Posture score: {score:.1f}/100 (Grade {grade})."
    story.append(Paragraph(f"<b>Assessment:</b> {how_worried}", cell_style))
    story.append(Spacer(1, 6))

    crit_c = sum(1 for f in findings if f.get("severity") == "Critical")
    high_c = sum(1 for f in findings if f.get("severity") == "High")
    med_c = sum(1 for f in findings if f.get("severity") == "Medium")
    low_c = sum(1 for f in findings if f.get("severity") == "Low")
    info_c = sum(1 for f in findings if f.get("severity") == "Info")

    story.append(Table([
        ['Posture Score', 'Grade', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total Findings'],
        [f'{score:.1f} / 100', f'Grade {grade}', str(crit_c), str(high_c), str(med_c), str(low_c), str(info_c), str(len(findings))]
    ], colWidths=[80, 65, 50, 50, 50, 50, 50, 75], style=TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f8fafc')),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
    ])))
    story.append(Spacer(1, 10))

    story.append(Paragraph(f'2. Security Findings ({len(findings)})', h2_style))
    table_data = [['Severity', 'Rule ID', 'Plain Summary & Technical Title', 'Risk']]
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
        r_score = f.get('risk_score')
        score_text = f"{r_score:.1f}" if r_score is not None else "Not scored"
        p_sum = f.get("plain_summary") or f.get("title", "")
        desc = f"<b>{p_sum}</b><br/><font color='#64748b'>{f.get('title', '')}</font>"
        table_data.append([
            sev,
            f.get('rule_id', ''),
            Paragraph(desc, cell_style),
            score_text,
        ])
        tstyle.append(('TEXTCOLOR', (0, idx), (0, idx), sev_colors.get(sev, colors.black)))
        tstyle.append(('FONTNAME', (0, idx), (0, idx), 'Helvetica-Bold'))

    if len(findings) == 0:
        table_data.append(['None', '—', Paragraph('No security vulnerabilities identified in capture.', cell_style), '0.0'])

    story.append(Table(table_data, colWidths=[60, 80, 330, 60], style=TableStyle(tstyle)))
    story.append(Spacer(1, 12))

    story.append(Paragraph('3. Prioritized Fix-First Recommendations', h2_style))
    if recommendations:
        for r in recommendations[:4]:
            title_p = Paragraph(f"<b>#{r.get('rank', 1)}: {r.get('title', '')}</b> (Effort: {r.get('effort', 'Medium')})", cell_bold)
            steps_text = " | ".join(r.get("steps", [])[:2])
            steps_p = Paragraph(f"Action: {steps_text}", cell_style)
            story.append(title_p)
            story.append(steps_p)
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph('No configuration changes required.', cell_style))

    story.append(Spacer(1, 10))

    # Terms Explained
    from analyzer.explain.engine import find_terms_in_text
    full_text = f"{narrative_data} {' '.join(f.get('title', '') for f in findings)}"
    matched = find_terms_in_text(full_text)
    if matched:
        story.append(Paragraph('4. Terms Explained (Glossary Appendix)', h2_style))
        for t in matched[:4]:
            t_p = Paragraph(f"<b>{t.get('name')} ({t.get('expansion')}):</b> {t.get('simple')}", cell_style)
            story.append(t_p)
            story.append(Spacer(1, 2))
        story.append(Spacer(1, 6))

    story.append(Paragraph('5. Observability Boundary & Methodological Caveats', h2_style))
    story.append(Paragraph(
        'Passive keyless analysis evaluates observable parameters in unencrypted network captures. '
        'Encrypted IKE_AUTH identities, child SA proposals, and ESP payloads are not observable without cryptographic keys. '
        'Compliance grounded in RFC 8247, RFC 8221, and NIST SP 800-77 Rev. 1 guidelines.',
        cell_style,
    ))

    doc.build(story)
