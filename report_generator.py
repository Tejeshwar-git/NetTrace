from fpdf import FPDF
from datetime import datetime

class ForensicPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'OFFICIAL DIGITAL FORENSICS AUDIT REPORT', border=False, ln=True, align='C')
        self.set_font('Helvetica', 'I', 9)
        self.cell(0, 5, f'Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC', border=False, ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - ISO/IEC 27037 Forensic Chain of Custody Verified', align='C')

def create_pdf_report(case_id, investigator_name, badge_id, reports):
    pdf = ForensicPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Header Information
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, f'CASE FILE: {case_id}', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, f'Lead Investigator: {investigator_name} (Badge ID: {badge_id})', ln=True)
    pdf.cell(0, 6, f'Status: ACTIVE / VERIFIED', ln=True)
    pdf.ln(5)
    
    # Evidence Table Section
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Attached Case Evidence Runs & Hashes', ln=True)
    pdf.set_font('Helvetica', '', 10)
    
    if not reports:
        pdf.cell(0, 6, 'No evidence runs committed to this case file yet.', ln=True)
    else:
        for idx, r in enumerate(reports, 1):
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 6, f'Evidence Run #{idx}: {r[0]} ({r[1]})', ln=True)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(0, 5, f'  - SHA-256 Hash: {r[2]}', ln=True)
            pdf.cell(0, 5, f'  - Calculated Threat Score: {r[3]}%', ln=True)
            pdf.cell(0, 5, f'  - Timestamp Logged: {r[4]}', ln=True)
            pdf.ln(3)
            
    return bytes(pdf.output())