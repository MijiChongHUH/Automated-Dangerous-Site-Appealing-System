"""
vendors/email_sender.py
=======================
Gmail API-based email sender for false positive reports.

Collects all dangerous/flagged domains from a VirusTotal check run,
groups them by which vendors flagged them, then sends ONE email per
vendor (that has an email address configured) listing all affected domains.

Setup
─────
1. Go to https://console.cloud.google.com/
2. Create a project → Enable Gmail API
3. Create OAuth 2.0 credentials (Desktop app type)
4. Add to .env:
     GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com
     GMAIL_CLIENT_SECRET=your_client_secret
     GMAIL_SENDER=bk8idol8888@gmail.com

5. First run will open a browser to authorize Gmail access.
   A token.json file will be saved locally for future runs.

6. pip install --break-system-packages google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client

Vendor email registry
─────────────────────
Add/remove vendors and their email addresses in VENDOR_EMAILS below.
The key must match the vendor name as it appears in VirusTotal results
(case-insensitive matching is applied automatically).
"""

import os
import json
import base64
import logging
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("[ERROR] Google API libraries not installed.")
    print("        Run: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")
    raise

# ─── Configuration ────────────────────────────────────────────────────────────

SCOPES       = ["https://www.googleapis.com/auth/gmail.send"]
TOKEN_FILE   = "token.json"
SENDER_EMAIL = os.getenv("GMAIL_SENDER", "bkworklinda@gmail.com")

# OAuth credentials loaded from .env
_CLIENT_CONFIG = {
    "installed": {
        "client_id":                  os.getenv("GMAIL_CLIENT_ID", ""),
        "client_secret":              os.getenv("GMAIL_CLIENT_SECRET", ""),
        "auth_uri":                   "https://accounts.google.com/o/oauth2/auth",
        "token_uri":                  "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris":              ["http://localhost"],
    }
}

# ─── Vendor email registry ────────────────────────────────────────────────────
# Key   = vendor name as it appears in VirusTotal (lowercase for matching)
# Value = recipient email address

VENDOR_EMAILS = {
    "seclookup":  "info@seclookup.com",
    "adminus":     "falsepositive@adminuslabs.net",
    # Add more vendors here as needed
}

# ─── Template ─────────────────────────────────────────────────────────────────

TEMPLATE = json.loads(Path("template.json").read_text())


def _build_subject(vendor_name: str, domain_count: int) -> str:
    if domain_count == 1:
        return f"False Positive Report — {vendor_name}"
    return f"False Positive Report — {domain_count} Domains — {vendor_name}"


def _build_body(vendor_name: str, domains_info: list[dict]) -> str:
    """
    Build the email body listing all affected domains.

    domains_info: list of {
        'url': str,
        'detection_type': str,
        'date_flagged': str,
    }
    """
    company = TEMPLATE.get("company_name", "BK8 Support")
    email   = TEMPLATE.get("requestor_email", SENDER_EMAIL)

    lines = []
    lines.append(f"Dear {vendor_name} Team,")
    lines.append("")
    lines.append("Please be informed that this is not a spam email. We are submitting false positive "
                 "reports for domain(s) that have been incorrectly flagged as malicious or suspicious "
                 "by your security systems.")
    lines.append("")

    if len(domains_info) == 1:
        d = domains_info[0]
        lines.append("Details:")
        lines.append(f"  * Website URL    : {d['url']}")
        lines.append(f"  * Detection Type : {d['detection_type']}")
        lines.append(f"  * Date Flagged   : {d['date_flagged']}")
    else:
        lines.append(f"The following {len(domains_info)} domain(s) have been incorrectly flagged:")
        lines.append("")
        for i, d in enumerate(domains_info, 1):
            lines.append(f"  {i}. URL            : {d['url']}")
            lines.append(f"     Detection Type : {d['detection_type']}")
            lines.append(f"     Date Flagged   : {d['date_flagged']}")
            lines.append("")

    lines.append("All listed domains belong to BK8 Support and are legitimate online gaming platforms.")
    lines.append("We kindly request a review of these detections and removal of the false positive "
                 "classifications from your systems.")
    lines.append("")
    lines.append(f"For any inquiries, please contact: {email}")
    lines.append("")
    lines.append("Regards,")
    lines.append(company)

    return "\n".join(lines)


# ─── Gmail API auth ───────────────────────────────────────────────────────────

def _get_gmail_service():
    """
    Authenticate with Gmail API using OAuth2.
    Opens browser on first run to authorize. Saves token.json for reuse.
    """
    if not _CLIENT_CONFIG["installed"]["client_id"]:
        raise ValueError(
            "GMAIL_CLIENT_ID not set in .env. "
            "Add your OAuth client ID and secret to .env."
        )
    if not _CLIENT_CONFIG["installed"]["client_secret"]:
        raise ValueError(
            "GMAIL_CLIENT_SECRET not set in .env. "
            "Add your OAuth client secret to .env."
        )

    creds = None

    # Load saved token
    if Path(TOKEN_FILE).exists():
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # Refresh or re-authorize if needed
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print(f"  [EMAIL] Refreshing Gmail token...")
            creds.refresh(Request())
        else:
            print(f"  [EMAIL] Opening browser for Gmail authorization...")
            flow = InstalledAppFlow.from_client_config(_CLIENT_CONFIG, SCOPES)
            creds = flow.run_local_server(port=8080)

        # Save token for next run
        Path(TOKEN_FILE).write_text(creds.to_json())
        print(f"  [EMAIL] Token saved to {TOKEN_FILE}")

    return build("gmail", "v1", credentials=creds)


# ─── Send email ───────────────────────────────────────────────────────────────

def _send_email(service, to: str, subject: str, body: str) -> bool:
    """Send a plain-text email via Gmail API. Returns True on success."""
    try:
        msg             = MIMEMultipart("alternative")
        msg["From"]     = SENDER_EMAIL
        msg["To"]       = to
        msg["Subject"]  = subject
        msg.attach(MIMEText(body, "plain"))

        raw     = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        message = service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()

        print(f"  [EMAIL] ✅  Sent to {to} (Message ID: {message.get('id', '?')})")
        return True

    except HttpError as e:
        print(f"  [EMAIL] ❌  Gmail API error: {e}")
        return False
    except Exception as e:
        print(f"  [EMAIL] ❌  Unexpected error: {e}")
        return False


# ─── Main function ────────────────────────────────────────────────────────────

def send_false_positive_emails(results: list[dict]) -> dict[str, bool]:
    """
    Given a list of VT check results, collect all dangerous/suspicious domains,
    group them by which vendor flagged them, and send ONE email per vendor
    that has an email address in VENDOR_EMAILS.

    Args:
        results: list of result dicts from checker.py — each has:
                 { 'url', 'malicious', 'suspicious', 'flagged_by', ... }

    Returns:
        dict of { vendor_name: True/False } indicating send success.
    """
    print(f"\n{'═'*60}")
    print(f"  EMAIL SENDER — False Positive Reports")
    print(f"{'═'*60}")

    # ── Collect flagged domains ────────────────────────────────────────────────
    # Build: { vendor_lower: [ {url, detection_type, date_flagged}, ... ] }
    vendor_domains: dict[str, list[dict]] = {}
    date_today = datetime.now().strftime("%m/%d/%Y")

    for result in results:
        if "error" in result:
            continue
        if not result.get("malicious", 0) and not result.get("suspicious", 0):
            continue

        url        = result.get("url", "")
        flagged_by = result.get("flagged_by", {})

        for vendor, verdict in flagged_by.items():
            vendor_lower = vendor.lower()
            if vendor_lower not in vendor_domains:
                vendor_domains[vendor_lower] = []
            vendor_domains[vendor_lower].append({
                "url":            url,
                "detection_type": verdict.capitalize() if verdict else "Malicious",
                "date_flagged":   date_today,
            })

    if not vendor_domains:
        print(f"  [EMAIL] No flagged domains found — no emails to send.")
        return {}

    # ── Match vendors to email addresses ──────────────────────────────────────
    to_send = {}   # { vendor_lower: (display_name, email, [domains]) }

    for vendor_lower, domains in vendor_domains.items():
        if vendor_lower in VENDOR_EMAILS:
            to_send[vendor_lower] = (
                vendor_lower.title(),
                VENDOR_EMAILS[vendor_lower],
                domains,
            )

    if not to_send:
        print(f"  [EMAIL] Flagged vendors with no email configured:")
        for v, domains in vendor_domains.items():
            print(f"    • {v} ({len(domains)} domain(s)) — add to VENDOR_EMAILS to enable")
        return {}

    # Show what will be sent
    print(f"  [EMAIL] Vendors to email: {len(to_send)}")
    for vendor_lower, (display, email, domains) in to_send.items():
        print(f"    • {display} → {email} ({len(domains)} domain(s))")
        for d in domains:
            print(f"        - {d['url']}")

    # ── Authenticate Gmail ────────────────────────────────────────────────────
    print(f"\n  [EMAIL] Authenticating Gmail API...")
    try:
        service = _get_gmail_service()
        print(f"  [EMAIL] ✅  Gmail authenticated as {SENDER_EMAIL}")
    except Exception as e:
        print(f"  [EMAIL] ❌  Gmail auth failed: {e}")
        return {v: False for v in to_send}

    # ── Send one email per vendor ─────────────────────────────────────────────
    send_results = {}
    for vendor_lower, (display_name, recipient_email, domains) in to_send.items():
        print(f"\n  [EMAIL] Sending to {display_name} <{recipient_email}>...")
        subject = _build_subject(display_name, len(domains))
        body    = _build_body(display_name, domains)

        if not recipient_email or "@" not in recipient_email:
            print(f"  [EMAIL] ⚠️   Invalid email address for {display_name} — skipping.")
            send_results[vendor_lower] = False
            continue

        ok = _send_email(service, recipient_email, subject, body)
        send_results[vendor_lower] = ok

    # ── Summary ───────────────────────────────────────────────────────────────
    sent    = sum(1 for ok in send_results.values() if ok)
    failed  = sum(1 for ok in send_results.values() if not ok)
    skipped = len(vendor_domains) - len(to_send)

    print(f"\n  [EMAIL] ── Summary ──")
    print(f"  [EMAIL]   ✅  Sent    : {sent}")
    print(f"  [EMAIL]   ❌  Failed  : {failed}")
    print(f"  [EMAIL]   ⏭️   Skipped : {skipped} (no email configured)")

    return send_results