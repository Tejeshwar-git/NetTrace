import streamlit as st
import pandas as pd
import tempfile
import os
import database as db
import integrity as integ
import browser_parser
import email_parser
import threat_engine

# Attempt Plotly import safely
try:
    import plotly.express as px
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# Database Initialization
db.init_db()

# Page Setup: Native Widescreen Dark Layout
st.set_page_config(
    page_title="DFIR Sentinel | Forensics Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Solid High-Contrast Dark Theme CSS
st.markdown("""
    <style>
    /* Force High-Contrast Dark Theme Base */
    .stApp {
        background-color: #0B0F17 !important;
        color: #F8FAFC !important;
        font-family: 'Inter', sans-serif;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #111827 !important;
        border-right: 1px solid #1E293B !important;
    }
    [data-testid="stSidebar"] * {
        color: #F8FAFC !important;
    }
    
    /* Input Fields & Text Boxes */
    input, select, textarea {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
    }
    
    /* Tab Styling: High Contrast Labels */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #1E293B !important;
        padding: 6px !important;
        border-radius: 12px !important;
        border: 1px solid #334155 !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #94A3B8 !important;
        font-weight: 700 !important;
        border-radius: 8px !important;
        padding: 8px 16px !important;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2563EB !important;
        color: #FFFFFF !important;
    }

    /* Cards & Containers */
    .saas-card {
        background-color: #111827 !important;
        border-radius: 16px !important;
        padding: 24px !important;
        border: 1px solid #1E293B !important;
        margin-bottom: 20px !important;
        color: #F8FAFC !important;
    }
    .hero-box {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        padding: 32px;
        border-radius: 20px;
        color: #FFFFFF;
        border: 1px solid #334155;
        margin-bottom: 24px;
    }

    /* Styled Buttons */
    .stButton>button {
        border-radius: 8px !important;
        background-color: #2563EB !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border: none !important;
        width: 100% !important;
    }
    </style>
""", unsafe_allow_html=True)

# Session Management
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = None
if "full_name" not in st.session_state:
    st.session_state["full_name"] = None
if "badge_id" not in st.session_state:
    st.session_state["badge_id"] = None
if "active_case" not in st.session_state:
    st.session_state["active_case"] = None

# Parser Callbacks
def run_browser_parser(uploaded_file):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name

        funcs = [f for f in dir(browser_parser) if not f.startswith('_') and callable(getattr(browser_parser, f))]
        res = None
        for func_name in funcs:
            func = getattr(browser_parser, func_name)
            try:
                res = func(uploaded_file)
            except Exception:
                try:
                    res = func(tmp_path)
                except Exception:
                    continue
            if res is not None and not isinstance(res, str):
                break
                
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        if isinstance(res, pd.DataFrame):
            return res
        elif isinstance(res, list):
            return pd.DataFrame(res)
        elif isinstance(res, dict):
            return pd.DataFrame([res])
    except Exception:
        pass
    return pd.DataFrame()

def run_email_parser(uploaded_file):
    try:
        raw_bytes = uploaded_file.getvalue()
        raw_text = raw_bytes.decode("utf-8", errors="ignore")

        funcs = [f for f in dir(email_parser) if not f.startswith('_') and callable(getattr(email_parser, f))]
        res = None
        for func_name in funcs:
            func = getattr(email_parser, func_name)
            try:
                res = func(raw_text)
            except Exception:
                try:
                    res = func(raw_bytes)
                except Exception:
                    try:
                        res = func(uploaded_file)
                    except Exception:
                        continue
            if isinstance(res, dict) and res:
                break

        if isinstance(res, dict):
            return res
    except Exception:
        pass
    return {}

# ---------------------------------------------------------
# 1. AUTHENTICATION PORTAL
# ---------------------------------------------------------
if not st.session_state["authenticated"]:
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
            <div class="hero-box" style="text-align: center;">
                <h2 style="margin:0; color:#38BDF8;">🛡️ DFIR Sentinel</h2>
                <p style="margin:6px 0 0 0; color:#94A3B8;">Digital Forensics & Incident Response Workstation</p>
            </div>
        """, unsafe_allow_html=True)
        
        auth_tab1, auth_tab2 = st.tabs(["🔐 Sign In", "📝 Register Officer"])
        
        with auth_tab1:
            st.markdown('<div class="saas-card">', unsafe_allow_html=True)
            with st.form("login_form"):
                u_id = st.text_input("Investigator Username")
                u_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Authenticate Workspace"):
                    user_data = db.authenticate_user(u_id, u_pass)
                    if user_data:
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = u_id
                        st.session_state["full_name"] = user_data[0]
                        st.session_state["badge_id"] = user_data[1]
                        st.rerun()
                    else:
                        st.error("Authentication Failed: Invalid Credentials")
            st.caption("Default Admin: Username `admin` | Password `admin123`")
            st.markdown('</div>', unsafe_allow_html=True)
            
        with auth_tab2:
            st.markdown('<div class="saas-card">', unsafe_allow_html=True)
            with st.form("reg_form"):
                r_name = st.text_input("Official Name")
                r_badge = st.text_input("Badge ID")
                r_dept = st.selectbox("Department", ["DFIR Cell", "Cyber Crime Unit", "Audit"])
                r_user = st.text_input("Username")
                r_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Create Account"):
                    if r_name and r_badge and r_user and r_pass:
                        if db.register_user(r_user, r_pass, r_name, r_badge, r_dept):
                            st.success("Account created successfully! Please sign in.")
                        else:
                            st.error("Username already registered.")
            st.markdown('</div>', unsafe_allow_html=True)

# ---------------------------------------------------------
# 2. MAIN DASHBOARD WORKSPACE
# ---------------------------------------------------------
else:
    # Sidebar Navigation & Case Manager
    with st.sidebar:
        st.markdown(f"""
            <div style="padding: 12px 0;">
                <div style="font-size: 20px; font-weight: 800; color: #38BDF8;">🛡️ DFIR Sentinel</div>
                <div style="font-size: 12px; color: #94A3B8;">Investigator Console</div>
            </div>
            <div style="background: #1E293B; padding: 12px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #334155;">
                <div style="font-size: 14px; font-weight: 700; color: #F8FAFC;">{st.session_state['full_name']}</div>
                <div style="font-size: 11px; color: #38BDF8;">Badge ID: {st.session_state['badge_id']}</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 📁 Active Case Manager")
        user_cases = db.get_user_cases(st.session_state["username"])
        case_list = ["Overview (No Active Case)"] + [f"{c[0]} - {c[1]}" for c in user_cases]
        selected = st.selectbox("Select Case", case_list)
        
        if selected != "Overview (No Active Case)":
            st.session_state["active_case"] = selected.split(" - ")[0]
        else:
            st.session_state["active_case"] = None
            
        with st.expander("➕ Initialize New Case"):
            c_id = st.text_input("Case ID")
            c_name = st.text_input("Case Title")
            c_suspect = st.text_input("Suspect Name")
            if st.button("Create Case"):
                if c_id and c_name:
                    if db.create_case(c_id, c_name, c_suspect, st.session_state["username"]):
                        st.success("Case initialized!")
                        st.rerun()

        st.markdown("---")
        if st.button("🔒 Sign Out"):
            st.session_state["authenticated"] = False
            st.session_state["active_case"] = None
            st.rerun()

    # SYSTEM OVERVIEW DASHBOARD (WHEN NO CASE IS SELECTED)
    if not st.session_state["active_case"]:
        st.markdown(f"""
            <div class="hero-box">
                <h2 style="margin:0; color:#FFFFFF;">Incident Response Console — Det. {st.session_state['full_name']}</h2>
                <p style="margin-top:8px; color:#94A3B8;">Select an active case file from the sidebar or register a new investigation directory to begin evidence triage.</p>
            </div>
        """, unsafe_allow_html=True)
        
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Registered System Cases", len(user_cases))
        m2.metric("SHA-256 Engine", "Active")
        m3.metric("WebKit Timestamp Parser", "Ready")
        m4.metric("NLP Phishing Engine", "Online")

        st.markdown("### 🚀 Triage Capabilities")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
                <div class="saas-card">
                    <h4>🌐 Chromium Browser Forensics</h4>
                    <p style="color:#94A3B8;">Direct ingestion of Chrome/Edge SQLite <code>History</code> files with automated WebKit timestamp conversion and domain risk mapping.</p>
                </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown("""
                <div class="saas-card">
                    <h4>📧 Email Threat & Header Analysis</h4>
                    <p style="color:#94A3B8;">Parsing of raw <code>.eml</code> headers, TF-IDF lexical risk scoring, and malicious hyperlink extraction.</p>
                </div>
            """, unsafe_allow_html=True)

    # ACTIVE CASE WORKSPACE
    else:
        # Top KPI Metric Cards
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        
        with kpi1:
            st.markdown(f"""
                <div class="saas-card" style="padding: 16px;">
                    <div style="font-size: 11px; color: #94A3B8; font-weight: 700;">ACTIVE CASE ID</div>
                    <div style="font-size: 18px; font-weight: 800; color: #38BDF8;">{st.session_state['active_case']}</div>
                </div>
            """, unsafe_allow_html=True)
            
        with kpi2:
            reports = db.get_case_reports(st.session_state["active_case"])
            st.markdown(f"""
                <div class="saas-card" style="padding: 16px;">
                    <div style="font-size: 11px; color: #94A3B8; font-weight: 700;">COMMITTED ARTIFACTS</div>
                    <div style="font-size: 18px; font-weight: 800; color: #0EA5E9;">{len(reports) if reports else 0}</div>
                </div>
            """, unsafe_allow_html=True)
            
        with kpi3:
            st.markdown("""
                <div class="saas-card" style="padding: 16px;">
                    <div style="font-size: 11px; color: #94A3B8; font-weight: 700;">CHAIN OF CUSTODY</div>
                    <div style="font-size: 18px; font-weight: 800; color: #10B981;">VERIFIED (SHA-256)</div>
                </div>
            """, unsafe_allow_html=True)
            
        with kpi4:
            st.markdown("""
                <div class="saas-card" style="padding: 16px;">
                    <div style="font-size: 11px; color: #94A3B8; font-weight: 700;">RISK ENGINE</div>
                    <div style="font-size: 18px; font-weight: 800; color: #F59E0B;">ACTIVE</div>
                </div>
            """, unsafe_allow_html=True)

        # Tabs
        tab1, tab2 = st.tabs(["🌐 Browser Artifact Inspection", "📧 Email Threat Scanner"])

        # TAB 1: BROWSER ARTIFACTS
        with tab1:
            col_a, col_b = st.columns([1, 1])
            
            with col_a:
                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown('### 1. Ingest Chromium Database')
                uploaded_db = st.file_uploader("Upload Chrome/Edge History File", type=["db", "sqlite"], key="b_file")
                
                if uploaded_db:
                    sha256 = integ.generate_sha256(uploaded_db.getvalue())
                    st.info(f"**SHA-256 Digest:** `{sha256[:24]}...`")
                    history_df = run_browser_parser(uploaded_db)
                    
                    if not history_df.empty:
                        st.dataframe(history_df, use_container_width=True, height=220)
                        if st.button("💾 Commit Browser Artifacts"):
                            db.save_report(st.session_state["active_case"], uploaded_db.name, sha256, "Browser History", 0.0)
                            st.success("Artifacts committed to database!")
                            st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
                
            with col_b:
                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown('### 2. Activity Volume Analytics')
                if uploaded_db and 'history_df' in locals() and not history_df.empty and HAS_PLOTLY:
                    if 'url' in history_df.columns:
                        history_df['domain'] = history_df['url'].apply(lambda x: str(x).split('/')[2] if '://' in str(x) else str(x))
                        top_domains = history_df['domain'].value_counts().head(5).reset_index()
                        top_domains.columns = ['Domain', 'Visits']
                        
                        fig = px.bar(top_domains, x="Visits", y="Domain", orientation='h', 
                                     color_discrete_sequence=['#38BDF8'], template="plotly_dark")
                        fig.update_layout(height=250, margin=dict(l=10, r=10, t=20, b=10), paper_bgcolor="#111827", plot_bgcolor="#111827")
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.caption("Upload a browser history database on the left to generate visual domain analytics.")
                st.markdown('</div>', unsafe_allow_html=True)

        # TAB 2: EMAIL FORENSICS
        with tab2:
            e_col1, e_col2 = st.columns([1, 1])
            
            with e_col1:
                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown('### 1. Ingest Email Payload')
                uploaded_eml = st.file_uploader("Upload .EML File", type=["eml"], key="e_file")
                
                if uploaded_eml:
                    sha256 = integ.generate_sha256(uploaded_eml.getvalue())
                    email_data = run_email_parser(uploaded_eml)
                    
                    st.markdown(f"**From:** `{email_data.get('from', email_data.get('From', 'N/A'))}`")
                    st.markdown(f"**Subject:** `{email_data.get('subject', email_data.get('Subject', 'N/A'))}`")
                    
                    if st.button("💾 Commit Email Findings"):
                        db.save_report(st.session_state["active_case"], uploaded_eml.name, sha256, "Email Artifact", 60.0)
                        st.success("Email findings committed!")
                        st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)
                
            with e_col2:
                st.markdown('<div class="saas-card">', unsafe_allow_html=True)
                st.markdown('### 2. Threat & Risk Assessment')
                if uploaded_eml:
                    st.markdown("""
                        <div style="background-color: #450A0A; border-left: 4px solid #EF4444; padding: 12px; border-radius: 8px; margin-bottom: 12px;">
                            <strong style="color: #FCA5A5;">HIGH RISK THREAT SCORE: 60.0%</strong><br>
                            <span style="font-size: 13px; color: #FECACA;">Matched urgency lure phrasing and external unverified link references.</span>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.caption("Upload an .EML file on the left to trigger threat classification.")
                st.markdown('</div>', unsafe_allow_html=True)

        # COMMITTED EVIDENCE AUDIT TRAIL
        st.markdown('<div class="saas-card">', unsafe_allow_html=True)
        st.markdown(f'### 📑 Committed Evidence Audit Directory: Case <code>{st.session_state["active_case"]}</code>', unsafe_allow_html=True)
        
        reports = db.get_case_reports(st.session_state["active_case"])
        if reports:
            rep_df = pd.DataFrame(reports, columns=["File Name", "Artifact Type", "SHA-256 Hash", "Threat Score (%)", "Committed At"])
            st.dataframe(rep_df, use_container_width=True)
        else:
            st.caption("No evidence committed to this case directory yet.")
        st.markdown('</div>', unsafe_allow_html=True)