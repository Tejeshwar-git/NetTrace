import email
from email import policy
from email.parser import BytesParser
import re

def parse_eml_content(raw_bytes: bytes) -> dict:
    """
    Parses RFC-822 / .EML raw bytes into sender, subject, date, 
    and extracted body text + hyperlinked URLs without external dependencies.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        try:
            msg = email.message_from_bytes(raw_bytes)
        except Exception as e:
            print(f"[email_parser] Failed basic MIME parse: {e}")
            msg = None

    if msg is None:
        raw_text = raw_bytes.decode("utf-8", errors="ignore")
        return {
            "from": "Unknown Sender",
            "subject": "Extracted Raw Stream",
            "date": "N/A",
            "body": raw_text,
            "urls": list(set(re.findall(r'https?://[^\s<>"\')]+', raw_text)))
        }

    sender = str(msg.get("From", "Unknown Sender"))
    subject = str(msg.get("Subject", "No Subject"))
    date = str(msg.get("Date", "Unknown Date"))

    body_text = ""
    html_content = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="ignore")
                    if content_type == "text/plain":
                        body_text += "\n" + decoded
                    elif content_type == "text/html":
                        html_content += "\n" + decoded
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="ignore")
                if msg.get_content_type() == "text/html":
                    html_content = decoded
                else:
                    body_text = decoded
            else:
                body_text = str(msg.get_payload() or "")
        except Exception:
            body_text = str(msg.get_payload() or "")

    # Basic regex strip if HTML was the only body
    if not body_text.strip() and html_content:
        body_text = re.sub(r"<[^>]+>", " ", html_content)

    combined_text = (body_text + " " + html_content).strip()
    urls_found = list(set(re.findall(r'https?://[^\s<>"\')]+', combined_text)))

    return {
        "from": sender,
        "subject": subject,
        "date": date,
        "body": body_text.strip(),
        "urls": urls_found
    }