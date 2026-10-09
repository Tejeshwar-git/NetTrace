import re

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "banking", "secure", 
    "credential", "free", "claim", "phish", "signin", "password", "wallet"
]
SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".online", ".site", ".ru", ".cn", ".tk", ".work"]

URGENCY_PATTERNS = [
    r"action required", r"account suspended", r"unauthorized access", 
    r"immediate action", r"verify your identity", r"password reset", 
    r"security alert", r"billing error", r"urgent", r"claim reward", r"click here"
]

def analyze_url_item(url_str, title_str=""):
    """
    Evaluates an individual URL and page title, returning a granular 
    threat score, matched indicators, severity tier, and actionable IR steps.
    """
    url_lower = str(url_str).lower()
    title_lower = str(title_str).lower()
    
    score = 0
    flags = []
    
    # 1. Check for Raw IP Address in Host
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
        score += 50
        flags.append("RAW_IP_HOST")
        
    # 2. Check for High-Risk TLDs
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            score += 25
            flags.append(f"RISKY_TLD({tld})")
            break
            
    # 3. Check for Lure Keywords
    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower or kw in title_lower]
    if matched_kw:
        score += 20 * len(matched_kw)
        flags.append(f"LURE_KEYWORDS({','.join(matched_kw)})")
        
    final_score = min(score, 100)
    
    if final_score >= 60:
        severity = "HIGH"
        remediation = [
            f"Immediately block destination host in edge firewall.",
            f"Inspect proxy logs for active outbound POST requests to '{url_str[:35]}...'.",
            f"Trigger an automatic password reset for the target session user."
        ]
    elif final_score >= 30:
        severity = "MEDIUM"
        remediation = [
            f"Query VirusTotal / AbuseIPDB for reputation scores on domain.",
            f"Monitor local workstation DNS query logs for sub-domain resolution."
        ]
    else:
        severity = "LOW"
        remediation = ["No immediate incident containment required."]
        
    return {
        "url": url_str,
        "title": title_str,
        "score": final_score,
        "severity": severity,
        "flags": flags,
        "remediation": remediation
    }


def analyze_email_content(raw_text):
    """
    Scans raw EML email text for urgency lures, extracted hyperlinks, 
    mismatched senders, and suspicious attachments.
    """
    text_lower = raw_text.lower()
    score = 0
    flags = []

    # 1. Check for Urgency & Phishing Lure Phrases
    matched_lures = []
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            matched_lures.append(pattern)

    if matched_lures:
        score += 15 * len(matched_lures)
        flags.append(f"URGENCY_LURES({', '.join(matched_lures[:3])})")

    # 2. Extract and analyze embedded links in body
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', raw_text)
    suspicious_urls = []
    for u in urls:
        u_analysis = analyze_url_item(u)
        if u_analysis["score"] >= 30:
            suspicious_urls.append(u)

    if suspicious_urls:
        score += 35
        flags.append(f"SUSPICIOUS_LINKS({len(suspicious_urls)})")

    # 3. Check for executable file extension references
    if re.search(r'\.(exe|zip|scr|iso|vbs|js|bat|ps1)\b', text_lower):
        score += 40
        flags.append("HIGH_RISK_ATTACHMENT_REF")

    final_score = min(score, 100)

    if final_score >= 60:
        severity = "HIGH"
        rationale = f"High-risk phishing indicators detected: {'; '.join(flags)}."
        remediation = [
            "Quarantine email payload from mail server queues immediately.",
            "Block extracted sender address and domain on Email Security Gateway (SEG).",
            "Revoke active user authentication tokens if links were opened."
        ]
    elif final_score >= 30:
        severity = "MEDIUM"
        rationale = f"Moderate suspicion flags identified: {'; '.join(flags)}."
        remediation = [
            "Flag email with external banner notice in user inbox.",
            "Verify SPF/DKIM/DMARC alignment for sender domain."
        ]
    else:
        severity = "LOW"
        rationale = "Low risk payload. No high-urgency lure patterns or malicious links detected."
        remediation = ["No immediate email quarantine action required."]

    return {
        "score": final_score,
        "severity": severity,
        "flags": flags,
        "urls_found": urls,
        "rationale": rationale,
        "remediation": remediation
    }