"""
vendors/webroot.py
==================
Selenium-based false positive submission for Webroot.
Form URL: https://detail.webrootanywhere.com/servicetalk.asp?email={email}&source=&

The form is a simple support ticket page with:
  • Subject   : input[name='subject']       — free text (required)
  • Category  : select[name='prereq1']      — dropdown, we select "Threat Found - False Positive"
  • Message   : textarea (labelled Message) — free text (required)
  • Email     : pre-filled via URL query string parameter

No CAPTCHA detected — fully automated (no manual click needed).

Vendor name in VirusTotal: "Webroot"

Dependencies
────────────
  pip install selenium webdriver-manager

template.json keys used
────────────────────────
  requestor_email        — pre-filled in the URL (required)
  subject_template       — subject line fallback
  webroot_subject_template — dedicated subject (preferred)
    Placeholders: {domain}
  body_template          — message body fallback
  webroot_body_template  — dedicated message body (preferred)
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait, Select
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import (
        TimeoutException, NoSuchElementException, ElementNotInteractableException
    )
except ImportError:
    print("[ERROR] 'selenium' not installed. Run: pip install selenium webdriver-manager")
    raise

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("[ERROR] 'webdriver-manager' not installed. Run: pip install webdriver-manager")
    raise


VENDOR_NAME      = "Webroot"
CATEGORY_VALUE   = "Threat Found - False Positive"
TEMPLATE         = json.loads(Path("template.json").read_text())

# Build the form URL with email pre-filled
_EMAIL    = TEMPLATE["requestor_email"]
FORM_URL  = f"https://detail.webrootanywhere.com/servicetalk.asp?email={_EMAIL}&source=&"

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
    """Visible Chrome — lets us watch the submission."""
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    })
    return driver


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _ensure_scheme(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _build_subject(domain: str) -> str:
    tpl = TEMPLATE.get("webroot_subject_template",
                        TEMPLATE.get("subject_template",
                                     "False Positive Report: {domain}"))
    return tpl.format(domain=domain)


def _build_body(domain: str, flagged_by: dict) -> str:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")
    tpl = TEMPLATE.get("webroot_body_template",
                        TEMPLATE.get("body_template", ""))
    return tpl.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


def _safe_find(driver, css: str):
    """Return a displayed element or None."""
    try:
        el = driver.find_element(By.CSS_SELECTOR, css)
        return el if el.is_displayed() else None
    except NoSuchElementException:
        return None


def _safe_click(driver, el):
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(0.3)
        el.click()
    except ElementNotInteractableException:
        driver.execute_script("arguments[0].click();", el)


def _type_human(el, text: str):
    """Fill field instantly — no CAPTCHA on Webroot form."""
    el.clear()
    el.send_keys(text)



# ─── Cookie banner ─────────────────────────────────────────────────────────────

def _reject_cookies(driver):
    """Click Reject/Decline cookies button if a consent banner appears."""
    reject_keywords = ("reject", "decline", "deny", "necessary only",
                       "essential only", "refuse", "no, thanks")
    accept_keywords = ("accept", "agree", "allow", "consent")

    # Give banner up to 3s to appear
    time.sleep(1)

    for btn in driver.find_elements(By.TAG_NAME, "button"):
        txt = (btn.text or "").strip().lower()
        if any(kw in txt for kw in reject_keywords) and btn.is_displayed():
            try:
                btn.click()
                print(f"  [APPEAL] 🍪  Cookie banner rejected.")
                time.sleep(0.5)
                return
            except Exception:
                pass

    # Fallback: CSS selectors commonly used for reject buttons
    for sel in [
        "button[id*='reject' i]",
        "button[id*='decline' i]",
        "button[class*='reject' i]",
        "button[class*='decline' i]",
        "a[id*='reject' i]",
        "a[class*='reject' i]",
    ]:
        try:
            el = driver.find_element(By.CSS_SELECTOR, sel)
            if el.is_displayed():
                el.click()
                print(f"  [APPEAL] 🍪  Cookie banner rejected.")
                time.sleep(0.5)
                return
        except Exception:
            pass

    # If no reject button found, check if there's an accept-only banner
    # and skip it — don't accept cookies, just proceed
    print(f"  [APPEAL] 🍪  No cookie banner found (or already dismissed).")


# ─── Core form fill + submit ──────────────────────────────────────────────────

def _fill_and_submit(driver, domain: str, flagged_by: dict, debug: bool) -> bool:
    wait = WebDriverWait(driver, 25)

    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    try:
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "form")))
        time.sleep(3)
    except TimeoutException:
        print(f"  [APPEAL] ❌  Page did not load in time.")
        return False

    # ── Reject cookies if banner appears ─────────────────────────────────────
    _reject_cookies(driver)

    if debug:
        print(f"  [DEBUG] Title: {driver.title}")
        print(f"  [DEBUG] URL  : {driver.current_url}")
        for el in driver.find_elements(By.TAG_NAME, "input"):
            print(f"  [DEBUG] input  name={el.get_attribute('name')!r:25} "
                  f"type={el.get_attribute('type')!r:12} "
                  f"id={el.get_attribute('id')!r}")
        for el in driver.find_elements(By.TAG_NAME, "select"):
            print(f"  [DEBUG] select name={el.get_attribute('name')!r:25} "
                  f"id={el.get_attribute('id')!r}")
        for el in driver.find_elements(By.TAG_NAME, "textarea"):
            print(f"  [DEBUG] textarea name={el.get_attribute('name')!r:25} "
                  f"id={el.get_attribute('id')!r}")

    subject = _build_subject(domain)
    body    = _build_body(domain, flagged_by)

    # ── Subject ───────────────────────────────────────────────────────────────
    subject_field = (
        _safe_find(driver, "input[name='subject']") or
        _safe_find(driver, "input[name='Subject']") or
        _safe_find(driver, "input[placeholder*='ubject' i]")
    )
    if not subject_field:
        print(f"  [APPEAL] ❌  Subject field not found — aborting.")
        return False
    _type_human(subject_field, subject)
    print(f"  [APPEAL] ✏️   Subject  : {subject}")

    # ── Category dropdown ─────────────────────────────────────────────────────
    # select[name='prereq1'], value = "Threat Found - False Positive"
    try:
        select_el = driver.find_element(By.CSS_SELECTOR, "select[name='prereq1']")
        sel = Select(select_el)
        sel.select_by_value(CATEGORY_VALUE)
        print(f"  [APPEAL] ✏️   Category : {CATEGORY_VALUE}")
    except NoSuchElementException:
        # Fallback: try by id
        try:
            select_el = driver.find_element(By.CSS_SELECTOR, "select#reqselect")
            sel = Select(select_el)
            sel.select_by_value(CATEGORY_VALUE)
            print(f"  [APPEAL] ✏️   Category : {CATEGORY_VALUE}")
        except NoSuchElementException:
            print(f"  [APPEAL] ⚠️   Category dropdown not found — continuing.")
    except Exception as e:
        print(f"  [APPEAL] ⚠️   Could not select category: {e}")

    # ── Message ───────────────────────────────────────────────────────────────
    message_field = (
        _safe_find(driver, "textarea[name='message']") or
        _safe_find(driver, "textarea[name='Message']") or
        _safe_find(driver, "textarea[name='body']") or
        _safe_find(driver, "textarea")
    )
    if not message_field:
        print(f"  [APPEAL] ❌  Message field not found — aborting.")
        return False
    _type_human(message_field, body)
    print(f"  [APPEAL] ✏️   Message  : ({len(body)} chars)")
    if debug:
        print(f"  [DEBUG] Body:\n{body}\n")

    # ── Submit button ─────────────────────────────────────────────────────────
    submit_btn = (
        _safe_find(driver, "input[type='submit']") or
        _safe_find(driver, "button[type='submit']") or
        _safe_find(driver, "input[type='button'][value*='Send' i]") or
        _safe_find(driver, "input[type='button'][value*='Submit' i]")
    )
    if not submit_btn:
        # Try finding any button with send/submit text
        for btn in driver.find_elements(By.TAG_NAME, "input"):
            val = (btn.get_attribute("value") or "").lower()
            if any(kw in val for kw in ("send", "submit")):
                submit_btn = btn
                break
    if not submit_btn:
        print(f"  [APPEAL] ❌  Submit button not found — aborting.")
        return False

    btn_label = (submit_btn.get_attribute("value") or
                 submit_btn.text or "Submit")
    print(f"  [APPEAL] 🖱️   Clicking '{btn_label}'...")

    initial_url = driver.current_url
    _safe_click(driver, submit_btn)

    # ── Detect success ────────────────────────────────────────────────────────
    print(f"  [APPEAL] ⏳  Waiting for response...")

    end_time = time.time() + 20
    while time.time() < end_time:
        time.sleep(1)

        current_url = driver.current_url

        # URL change after submission
        if current_url != initial_url:
            if any(kw in current_url.lower() for kw in ("thank", "success", "sent", "confirm")):
                print(f"  [APPEAL] ✅  Redirected to success page: {current_url}")
                return True
            time.sleep(2)
            if driver.current_url != initial_url:
                print(f"  [APPEAL] ✅  Page navigated: {driver.current_url}")
                return True

        # Page text success keywords
        try:
            body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            success_kw = (
                "thank you", "message sent", "ticket created",
                "successfully", "received", "we will", "support request"
            )
            error_kw = (
                "error", "failed", "invalid", "required", "please fill"
            )
            if any(kw in body_text for kw in success_kw):
                print(f"  [APPEAL] ✅  Success message detected on page.")
                return True
            if any(kw in body_text for kw in error_kw):
                print(f"  [APPEAL] ❌  Error detected on page.")
                if debug:
                    print(f"  [DEBUG] Page text snippet: {body_text[:300]}")
                return False
        except Exception:
            pass

    print(f"  [APPEAL] ⚠️   No clear success signal after 20s.")
    print(f"  [APPEAL]     Check browser — form may still have submitted.")
    return False


# ─── Main entry ───────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a Webroot false positive support ticket via their web form.

    Fills Subject, selects 'Threat Found - False Positive' from the category
    dropdown, fills Message, then auto-clicks Send. No CAPTCHA present.

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Run Chrome without a visible window.
        debug      : Print extra diagnostics including all field names.

    Returns:
        True if submission confirmed, False on failure.
    """
    global _shared_driver

    domain     = _clean_domain(url)
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── Webroot (Selenium / auto-submit) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill + Auto-submit")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()
            own_driver = True

        ok = _fill_and_submit(driver, domain, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
            time.sleep(5)   # let user see success page
        else:
            print(f"  [APPEAL] ❌  Failed for: {domain}")

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