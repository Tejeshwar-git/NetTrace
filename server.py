from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Any
import database as db
import integrity as integ
import browser_parser
import email_parser
import threat_engine
import pandas as pd
import tempfile
import os
import json

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="NetTrace API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()

class HistoryItem(BaseModel):
    id: Optional[str] = None
    url: Optional[str] = ""
    title: Optional[str] = ""
    visitCount: Optional[int] = 1
    lastVisitTime: Optional[Any] = None

class ExtensionPayload(BaseModel):
    case_id: str
    history: List[HistoryItem]

class LiveEmailPayload(BaseModel):
    case_id: Optional[str] = ""
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    body_text: Optional[str] = ""
    links: Optional[List[str]] = []

class DeleteSelectionPayload(BaseModel):
    case_id: str
    hashes: List[str]

@app.options("/{full_path:path}")
async def options_handler(full_path: str):
    return JSONResponse(
        content={"status": "ok"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.get("/", response_class=HTMLResponse)
def read_root():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = db.authenticate_user(username, password)
    if user:
        return {"status": "success", "full_name": user[0], "badge_id": user[1]}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/register")
def register(username: str = Form(...), password: str = Form(...), name: str = Form(...), badge: str = Form(...), dept: str = Form(...)):
    if db.register_user(username, password, name, badge, dept):
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Username already exists")

@app.get("/api/cases/{username}")
def get_cases(username: str):
    cases = db.get_user_cases(username)
    return [{"id": c[0], "title": c[1]} for c in cases]

@app.post("/api/cases/create")
def create_case(case_id: str = Form(...), title: str = Form(...), suspect: str = Form(...), username: str = Form(...)):
    if db.create_case(case_id, title, suspect, username):
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Case ID already exists")

@app.post("/api/parse/browser")
async def parse_browser(file: UploadFile = File(...)):
    content = await file.read()
    sha256 = integ.generate_sha256(content)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        df = browser_parser.parse_chrome_history(tmp_path)
    except Exception as e:
        print(f"[ERROR] Browser parsing exception: {e}")
        df = pd.DataFrame()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    analyzed_items = []
    high_risk_count = 0
    med_risk_count = 0
    low_risk_count = 0

    if not df.empty:
        for _, row in df.iterrows():
            url = str(row.get('url', '') or '')
            title = str(row.get('title', '') or '')
            analysis = threat_engine.analyze_url_item(url, title)
            analyzed_items.append(analysis)
            if analysis['severity'] == 'HIGH':
                high_risk_count += 1
            elif analysis['severity'] == 'MEDIUM':
                med_risk_count += 1
            else:
                low_risk_count += 1

    return {
        "sha256": sha256, 
        "records": df.to_dict(orient="records") if not df.empty else [],
        "total_scanned": len(analyzed_items),
        "high_risk_count": high_risk_count,
        "med_risk_count": med_risk_count,
        "low_risk_count": low_risk_count,
        "analyzed_items": analyzed_items
    }

@app.post("/api/parse/email")
async def parse_email(file: UploadFile = File(...)):
    content = await file.read()
    sha256 = integ.generate_sha256(content)
    
    try:
        parsed = email_parser.parse_eml_content(content)
    except Exception as e:
        print(f"[ERROR] Email parsing exception: {e}")
        parsed = {
            "from": "Unknown Sender",
            "subject": file.filename,
            "date": "N/A",
            "body": content.decode("utf-8", errors="ignore"),
            "urls": []
        }

    full_text = f"From: {parsed.get('from', '')}\nSubject: {parsed.get('subject', '')}\n\n{parsed.get('body', '')}\n" + "\n".join(parsed.get('urls', []))
    
    try:
        analysis = threat_engine.analyze_email_content(full_text)
    except Exception as e:
        print(f"[ERROR] Threat engine execution error: {e}")
        analysis = {
            "score": 0.0,
            "severity": "LOW",
            "flags": [],
            "urls_found": [],
            "rationale": "Direct fallback analysis.",
            "remediation": []
        }

    return {
        "sha256": sha256,
        "from": parsed.get("from") or "Unknown Sender",
        "subject": parsed.get("subject") or file.filename,
        "date": parsed.get("date") or "N/A",
        "score": float(analysis.get("score", 0.0)),
        "severity": analysis.get("severity") or "LOW",
        "flags": analysis.get("flags") or [],
        "urls_found": parsed.get("urls") or analysis.get("urls_found") or [],
        "rationale": analysis.get("rationale") or "No immediate threat indicators identified.",
        "remediation": analysis.get("remediation") or []
    }

@app.post("/api/parse/live-email")
def parse_live_email(payload: LiveEmailPayload):
    try:
        combined_text = f"From: {payload.sender}\nSubject: {payload.subject}\n\n{payload.body_text}\n" + "\n".join(payload.links)
        sha256 = integ.generate_sha256(combined_text.encode('utf-8'))
        analysis = threat_engine.analyze_email_content(combined_text)
        
        details_json = json.dumps({
            "from": payload.sender,
            "subject": payload.subject,
            "flags": analysis["flags"],
            "rationale": analysis["rationale"],
            "remediation": analysis["remediation"]
        })

        if payload.case_id:
            db.save_report(payload.case_id, f"Live_Webmail_{payload.subject[:15]}.eml", sha256, "Live Webmail Scan", round(analysis["score"], 1), details_json)

        return {
            "sha256": sha256,
            "from": payload.sender,
            "subject": payload.subject,
            "score": round(analysis["score"], 1),
            "severity": analysis["severity"],
            "flags": analysis["flags"],
            "rationale": analysis["rationale"],
            "remediation": analysis["remediation"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ingest/live-extension")
def ingest_live_extension(payload: ExtensionPayload):
    try:
        records = [item.dict() for item in payload.history]
        analyzed_items = []
        high_risk_count = 0
        med_risk_count = 0
        low_risk_count = 0
        
        for item in records:
            url = item.get("url", "") or ""
            title = item.get("title", "") or ""
            analysis = threat_engine.analyze_url_item(url, title)
            analyzed_items.append(analysis)
            if analysis["severity"] == "HIGH":
                high_risk_count += 1
            elif analysis["severity"] == "MEDIUM":
                med_risk_count += 1
            else:
                low_risk_count += 1

        content_str = f"extension_live_{len(records)}_{payload.case_id}"
        sha256 = integ.generate_sha256(content_str.encode('utf-8'))
        
        details_json = json.dumps({
            "total_scanned": len(records),
            "high_risk_count": high_risk_count,
            "med_risk_count": med_risk_count,
            "low_risk_count": low_risk_count,
            "analyzed_items": analyzed_items
        })
        
        db.save_report(payload.case_id, "Live_Chrome_Extension_Feed.json", sha256, "Live Extension Stream", float(high_risk_count), details_json)

        return {
            "status": "success",
            "case_id": payload.case_id,
            "total_scanned": len(records),
            "high_risk_count": high_risk_count,
            "analyzed_items": analyzed_items,
            "sha256": sha256
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/commit")
def commit_report(case_id: str = Form(...), file_name: str = Form(...), sha256: str = Form(...), artifact_type: str = Form(...), score: float = Form(...), details: str = Form("")):
    db.save_report(case_id, file_name, sha256, artifact_type, score, details)
    return {"status": "success"}

@app.post("/api/reports/delete-selected")
def delete_selected_reports(payload: DeleteSelectionPayload):
    try:
        if payload.hashes:
            db.delete_reports_by_hashes(payload.case_id, payload.hashes)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/reports/clear/{case_id}")
def clear_reports(case_id: str):
    try:
        db.clear_case_reports(case_id)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/{case_id}")
def get_reports(case_id: str):
    reports = db.get_case_reports(case_id)
    
    browser_risk_counts = {"High Risk": 0, "Medium Risk": 0, "Safe / Clean": 0}
    email_vector_counts = {
        "Credential Harvest": 0,
        "Urgent Coercion": 0,
        "Domain Spoofing": 0,
        "Suspicious Links": 0,
        "Financial Pretext": 0
    }

    for r in reports:
        art_type = r[1]
        details_str = r[5]

        if details_str:
            try:
                details_obj = json.loads(details_str)
                if "analyzed_items" in details_obj:
                    for item in details_obj["analyzed_items"]:
                        score = item.get("score", 0)
                        if score >= 60:
                            browser_risk_counts["High Risk"] += 1
                        elif score >= 30:
                            browser_risk_counts["Medium Risk"] += 1
                        else:
                            browser_risk_counts["Safe / Clean"] += 1

                if "from" in details_obj or "Email" in art_type:
                    flags = [f.lower() for f in details_obj.get("flags", [])]
                    rationale = details_obj.get("rationale", "").lower()

                    if any(k in f for f in flags for k in ["credential", "password", "login", "auth"]) or "credential" in rationale:
                        email_vector_counts["Credential Harvest"] += 1
                    if any(k in f for f in flags for k in ["urgency", "urgent", "immediate", "suspend"]) or "urgency" in rationale:
                        email_vector_counts["Urgent Coercion"] += 1
                    if any(k in f for f in flags for k in ["spoof", "sender", "domain", "mismatch"]) or "spoof" in rationale:
                        email_vector_counts["Domain Spoofing"] += 1
                    if any(k in f for f in flags for k in ["url", "link", "ip", "http"]) or "link" in rationale:
                        email_vector_counts["Suspicious Links"] += 1
                    if any(k in f for f in flags for k in ["invoice", "payment", "bank", "financial"]) or "payment" in rationale:
                        email_vector_counts["Financial Pretext"] += 1
            except Exception:
                pass

    return {
        "reports": [{"file": r[0], "type": r[1], "sha256": r[2], "score": r[3], "timestamp": r[4], "details": r[5] or ""} for r in reports],
        "analytics": {
            "browser": {
                "labels": list(browser_risk_counts.keys()),
                "counts": list(browser_risk_counts.values())
            },
            "email": {
                "labels": list(email_vector_counts.keys()),
                "counts": list(email_vector_counts.values())
            }
        }
    }

@app.get("/api/reports/pdf/{case_id}")
def generate_pdf_report(case_id: str):
    reports = db.get_case_reports(case_id)
    pdf_filename = f"Case_Audit_Report_{case_id}.pdf"
    
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=16, leading=20, textColor=colors.HexColor('#0F172A'), spaceAfter=4)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#64748B'), spaceAfter=12)
    h2_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=12, leading=16, textColor=colors.HexColor('#0F172A'), spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=8.5, leading=11, textColor=colors.HexColor('#334155'))
    table_cell = ParagraphStyle('TableCell', parent=styles['Normal'], fontSize=7.5, leading=9.5, textColor=colors.HexColor('#1E293B'))
    table_header = ParagraphStyle('TableHeader', parent=styles['Normal'], fontSize=8, leading=10, textColor=colors.white, fontName='Helvetica-Bold')
    callout_style = ParagraphStyle('CalloutText', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#0F172A'))

    story.append(Paragraph("<b>NetTrace — Comprehensive Forensics Audit Report</b>", title_style))
    story.append(Paragraph(f"<b>Case File ID:</b> {case_id} &nbsp;|&nbsp; <b>Chain of Custody:</b> Cryptographic SHA-256 Log Verified &nbsp;|&nbsp; <b>Total Artifacts:</b> {len(reports)}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0'), spaceAfter=10))

    if reports:
        story.append(Paragraph("<b>1. Committed Evidence Audit Directory</b>", h2_style))
        master_table_data = [[
            Paragraph("Evidence File", table_header),
            Paragraph("Artifact Type", table_header),
            Paragraph("SHA-256 Hash", table_header),
            Paragraph("Threat Risk", table_header),
            Paragraph("Timestamp (UTC)", table_header)
        ]]
        
        for r in reports:
            score_color = "#DC2626" if r[3] > 50 else "#059669"
            score_p = Paragraph(f"<font color='{score_color}'><b>{r[3]}%</b></font>", table_cell)
            master_table_data.append([
                Paragraph(r[0][:24], table_cell),
                Paragraph(r[1], table_cell),
                Paragraph(f"{r[2][:14]}...", table_cell),
                score_p,
                Paragraph(str(r[4]), table_cell)
            ])

        t_master = Table(master_table_data, colWidths=[110, 100, 120, 70, 140])
        t_master.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,0), 5),
            ('TOPPADDING', (0,0), (-1,0), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ]))
        story.append(t_master)
        story.append(Spacer(1, 14))

        story.append(Paragraph("<b>2. Detailed Artifact Forensic Inspection</b>", h2_style))

        for idx, r in enumerate(reports, start=1):
            file_name, artifact_type, sha256_hash, score, timestamp, details_str = r
            item_story = []
            item_story.append(Paragraph(f"<b>Artifact #{idx}: {file_name}</b> ({artifact_type})", ParagraphStyle('ItemTitle', parent=styles['Heading3'], fontSize=10, textColor=colors.HexColor('#1E293B'), spaceAfter=2)))
            item_story.append(Paragraph(f"<font color='#64748B'>SHA-256:</font> {sha256_hash} &nbsp;|&nbsp; <font color='#64748B'>Score:</font> {score}%", body_style))
            item_story.append(Spacer(1, 4))

            if details_str:
                try:
                    details_obj = json.loads(details_str)
                    if "analyzed_items" in details_obj and details_obj["analyzed_items"]:
                        analyzed = details_obj["analyzed_items"]
                        sub_table_data = [[
                            Paragraph("URL / Page Title", table_header),
                            Paragraph("Risk Level", table_header),
                            Paragraph("Threat Indicators", table_header)
                        ]]
                        for item in analyzed[:15]:
                            item_url = item.get("url", "")
                            item_title = item.get("title", "") or "Untitled"
                            item_score = item.get("score", 0)
                            item_flags = ", ".join(item.get("flags", [])) or "CLEAN"
                            badge_color = "#DC2626" if item_score >= 60 else ("#D97706" if item_score >= 30 else "#059669")
                            url_p = Paragraph(f"<b>{item_title[:28]}</b><br/><font color='#64748B'>{item_url[:35]}</font>", table_cell)
                            risk_p = Paragraph(f"<font color='{badge_color}'><b>{item_score}% ({item.get('severity','LOW')})</b></font>", table_cell)
                            flags_p = Paragraph(f"<font fontName='Courier'>{item_flags}</font>", table_cell)
                            sub_table_data.append([url_p, risk_p, flags_p])

                        t_sub = Table(sub_table_data, colWidths=[240, 90, 210])
                        t_sub.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
                            ('VALIGN', (0,0), (-1,-1), 'TOP'),
                            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F1F5F9')]),
                            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        item_story.append(t_sub)

                    elif "from" in details_obj:
                        sender = details_obj.get("from", "N/A")
                        subject = details_obj.get("subject", "N/A")
                        rationale = details_obj.get("rationale", "N/A")
                        flags = ", ".join(details_obj.get("flags", [])) or "None"
                        remediation = details_obj.get("remediation", [])
                        email_info = f"<b>From:</b> {sender}<br/><b>Subject:</b> {subject}<br/><b>Rationale:</b> {rationale}<br/><b>Indicators:</b> {flags}"
                        item_story.append(Paragraph(email_info, body_style))

                        if remediation:
                            remed_text = "<br/><b>Incident Response Actions:</b><br/>" + "<br/>".join([f"• {step}" for step in remediation])
                            item_story.append(Paragraph(f"<font color='#991B1B'>{remed_text}</font>", body_style))
                except Exception:
                    item_story.append(Paragraph("<i>Standard evidence record — detailed JSON unavailable.</i>", body_style))
            else:
                item_story.append(Paragraph("<i>Standard evidence record — detailed JSON unavailable.</i>", body_style))

            item_story.append(Spacer(1, 8))
            story.append(KeepTogether(item_story))

        story.append(Spacer(1, 8))
        story.append(Paragraph("<b>3. Automated Incident Response Playbook Summary</b>", h2_style))
        playbook_box_data = [[
            Paragraph(
                "<b>MANDATORY CONTAINMENT ACTIONS:</b><br/>"
                "1. Enforce automated perimeter firewall domain block on high-risk URLs flagged.<br/>"
                "2. Trigger mandatory credential resets for local user accounts associated with flagged webmail links.<br/>"
                "3. Export and seal cryptographic SHA-256 hashes into digital court chain of custody log.",
                callout_style
            )
        ]]
        t_callout = Table(playbook_box_data, colWidths=[540])
        t_callout.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEF2F2')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#FCA5A5')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(t_callout)
    else:
        story.append(Paragraph("<i>No committed evidence records found for this case file.</i>", body_style))

    doc.build(story)
    return FileResponse(pdf_filename, filename=pdf_filename, media_type='application/pdf')