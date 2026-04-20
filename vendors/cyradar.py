"""
vendors/cyradar.py
==================
Selenium-based false positive submission for CyRadar.
Form URL: https://cyradar.com/reportfp/

The form uses reCAPTCHA v3 which blocks automated submissions.
This module auto-fills all fields, then PAUSES and waits for the
user to click the Send button manually. After the user clicks,
it detects the CF7 success response automatically.

Form structure (confirmed via debug inspection):
  • input[name='user-company']    — Company name  (required)
  • input[name='user-email']      — Email address (required)
  • input[name='user-phone']      — Telephone     (optional, left blank)
  • textarea[name='user-message'] — Message       (we fill this)
  • input[type='submit'].btn-primary — Send button (user clicks manually)
  • NO subject field
  • reCAPTCHA v3 (invisible) — reason we don't auto-click submit

Vendor name in VirusTotal: "CyRadar"

Dependencies
────────────
  pip install selenium webdriver-manager

template.json keys used
────────────────────────
  requestor_email       — sender email (required)
  company_name          — Company field value (required)
  body_template         — message body fallback
  cyradar_body_template — dedicated message body (preferred)
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
except ImportError:
    print("[ERROR] 'selenium' not installed. Run: pip install selenium webdriver-manager")
    raise

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("[ERROR] 'webdriver-manager' not installed. Run: pip install webdriver-manager")
    raise


VENDOR_NAME      = "CyRadar"
FORM_URL         = "https://cyradar.com/reportfp/"
TEMPLATE         = json.loads(Path("template.json").read_text())
USER_WAIT_SECS   = 120   # how long to wait for the user to click Send


# ─── Shared driver ────────────────────────────────────────────────────────────

_shared_driver = None


def set_shared_driver(driver):
    global _shared_driver
    _shared_driver = driver


def close_shared_driver():
    global _shared_driver
    if _shared_driver:
        try:
            _shared_driver.quit()
        except Exception:
            pass
        _shared_driver = None


# ─── Driver setup ─────────────────────────────────────────────────────────────

def _build_driver() -> webdriver.Chrome:
    """Always non-headless — user needs to see the form to click Send."""
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=opts)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _build_body(domain: str, flagged_by: dict) -> str:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")
    tpl = TEMPLATE.get("cyradar_body_template",
                        TEMPLATE.get("body_template", ""))
    return tpl.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


def _field_in_form(form_el, css: str):
    """Return a visible element scoped within form_el, or None."""
    try:
        el = form_el.find_element(By.CSS_SELECTOR, css)
        return el if el.is_displayed() else None
    except NoSuchElementException:
        return None


# ─── Core logic ───────────────────────────────────────────────────────────────

def _fill_form(driver, domain: str, flagged_by: dict, debug: bool) -> bool:
    """
    Load the page, fill all fields, then wait for user to click Send.
    Returns True if CF7 success is detected after submission.
    """
    wait = WebDriverWait(driver, 25)

    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    try:
        wait.until(EC.presence_of_element_located(
            (By.CSS_SELECTOR, "form.wpcf7-form")
        ))
        time.sleep(6)   # let CF7 + reCAPTCHA v3 fully initialise
    except TimeoutException:
        print(f"  [APPEAL] ❌  Timed out waiting for CF7 form.")
        return False

    if debug:
        print(f"  [DEBUG] Page title : {driver.title}")

    # ── Pick the ReportFP form (f2918), not the footer form (f77) ─────────────
    forms = driver.find_elements(By.CSS_SELECTOR, "form.wpcf7-form")
    if not forms:
        print(f"  [APPEAL] ❌  No CF7 forms found on page.")
        return False

    target_form = next(
        (f for f in forms if "f2918" in (f.get_attribute("action") or "")),
        forms[0]
    )

    if debug:
        print(f"  [DEBUG] Form action: {target_form.get_attribute('action')}")

    # ── Fill fields ───────────────────────────────────────────────────────────
    company      = TEMPLATE.get("company_name", "BK8 Support")
    sender_email = TEMPLATE["requestor_email"]
    body         = _build_body(domain, flagged_by)

    company_field = _field_in_form(target_form, "input[name='user-company']")
    if not company_field:
        print(f"  [APPEAL] ❌  Company field not found.")
        return False
    company_field.clear()
    company_field.send_keys(company)
    print(f"  [APPEAL] ✏️   Company : {company}")

    email_field = _field_in_form(target_form, "input[name='user-email']")
    if not email_field:
        print(f"  [APPEAL] ❌  Email field not found.")
        return False
    email_field.clear()
    email_field.send_keys(sender_email)
    print(f"  [APPEAL] ✏️   Email   : {sender_email}")

    phone_field = _field_in_form(target_form, "input[name='user-phone']")
    if phone_field:
        phone_field.clear()
        print(f"  [APPEAL] ✏️   Phone   : (left blank)")

    # Wait explicitly for the textarea to be present and visible
    try:
        WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located(
                (By.CSS_SELECTOR, "textarea[name='user-message']")
            )
        )
    except TimeoutException:
        print(f"  [APPEAL] ❌  Message field did not appear within 15s.")
        return False

    message_field = _field_in_form(target_form, "textarea[name='user-message']")
    if not message_field:
        print(f"  [APPEAL] ❌  Message field not found.")
        return False
    message_field.clear()
    message_field.send_keys(body)
    print(f"  [APPEAL] ✏️   Message : ({len(body)} chars)")

    # ── Scroll submit button into view so user can see it clearly ─────────────
    submit_btn = _field_in_form(target_form, "input[type='submit']")
    if submit_btn:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", submit_btn)

    # ── Prompt user to click Send ─────────────────────────────────────────────
    print(f"")
    print(f"  [APPEAL] ✅  Form filled. Browser window is ready.")
    print(f"  [APPEAL] 👉  Please click the SEND button in the browser now.")
    print(f"  [APPEAL]     Waiting up to {USER_WAIT_SECS}s for you to submit...")
    print(f"")

    # ── Wait for CF7 response output to appear (user clicked Send) ────────────
    try:
        WebDriverWait(driver, USER_WAIT_SECS).until(
            lambda d: d.find_element(
                By.CSS_SELECTOR, ".wpcf7-response-output"
            ).text.strip() != ""
        )

        resp_el  = driver.find_element(By.CSS_SELECTOR, ".wpcf7-response-output")
        resp_txt = resp_el.text.strip()
        resp_cls = resp_el.get_attribute("class") or ""

        if debug:
            print(f"  [DEBUG] Response class : {resp_cls}")
            print(f"  [DEBUG] Response text  : {resp_txt}")

        success_keywords = ("thank", "sent", "success", "received", "submitted")
        if "sent-ok" in resp_cls or any(kw in resp_txt.lower() for kw in success_keywords):
            print(f"  [APPEAL] ✅  Submission confirmed!")
            print(f"  [APPEAL]     Response: {resp_txt}")
            return True
        else:
            print(f"  [APPEAL] ❌  CF7 returned an error: {resp_txt}")
            return False

    except TimeoutException:
        # Check for redirect-based success
        if any(kw in driver.current_url.lower() for kw in ("thank", "success", "sent")):
            print(f"  [APPEAL] ✅  Redirected to success page: {driver.current_url}")
            return True

        print(f"  [APPEAL] ⚠️   No response detected after {USER_WAIT_SECS}s.")
        print(f"  [APPEAL]     Did you click Send? Check the browser window.")
        return False


# ─── Main entry ───────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Fill the CyRadar false positive form automatically, then wait for
    the user to click the Send button manually (bypasses reCAPTCHA).

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Ignored — always runs visible so user can click Send.
        debug      : Print extra diagnostics.

    Returns:
        True if confirmed submitted, False on failure or timeout.
    """
    global _shared_driver

    domain     = _clean_domain(url)
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── CyRadar (Selenium / manual send) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill → User clicks Send")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()   # always visible
            own_driver = True

        ok = _fill_form(driver, domain, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
        else:
            print(f"  [APPEAL] ❌  Failed for: {domain}")

        # Brief pause so user can see the success message before browser closes
        if ok:
            time.sleep(3)

        return ok

    except Exception as e:
        print(f"  [APPEAL] ERROR : {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return False

    finally:
        if own_driver and driver:
            try:
                driver.quit()
            except Exception:
                pass