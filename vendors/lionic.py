"""
vendors/lionic.py
=================
Selenium-based false positive submission for Lionic.
Form URL: https://www.lionic.com/supports/report-false-positive/

The form has a radio button at the top to select submission type.
We select: input[name='form_type'][value='AntiVirus-VT']
which reveals the VirusTotal false positive fields.

Workflow (same as cyradar.py):
  1. Open the page in a visible Chrome window.
  2. Accept the cookie banner if present.
  3. Select the radio button if present (for form type selection).
  4. Fill all visible fields automatically, including the required Subject field.
  5. Check the privacy policy checkbox.
  6. Auto-click the "Submit Only" button (Lionic has no CAPTCHA).
  7. Detects the success response and confirms in the terminal.

Vendor name in VirusTotal: "Lionic"

Dependencies
────────────
  pip install selenium webdriver-manager

template.json keys used
────────────────────────
  requestor_email      — sender email (required)
  requestor_name       — sender name  (falls back to company_name)
  company_name         — organisation/company field
  body_template        — comments/message body fallback
  lionic_body_template — dedicated message body (preferred)
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
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


VENDOR_NAME    = "Lionic"
FORM_URL       = "https://www.lionic.com/supports/report-false-positive/"
RADIO_VALUE    = "Website-VT"     # the radio button value to select
TEMPLATE       = json.loads(Path("template.json").read_text())
USER_WAIT_SECS = 120              # seconds to wait for user to click Submit

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


# ─── Driver ───────────────────────────────────────────────────────────────────

def _build_driver() -> webdriver.Chrome:
    """Always visible — shows the browser while submitting."""
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


def _ensure_scheme(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _build_subject(domain: str) -> str:
    tpl = TEMPLATE.get("subject_template", "False Positive Report: {domain}")
    return tpl.format(domain=domain)


def _build_body(domain: str, flagged_by: Dict[str, str]) -> str:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")
    tpl = TEMPLATE.get("lionic_body_template",
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
    """Click element, fall back to JS click if intercepted."""
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(0.3)
        el.click()
    except ElementNotInteractableException:
        driver.execute_script("arguments[0].click();", el)


def _print_all_fields(driver):
    """Debug helper — prints every form field found on the page."""
    print(f"\n  [DEBUG] ── All inputs ──")
    for el in driver.find_elements(By.TAG_NAME, "input"):
        print(f"    type={el.get_attribute('type')!r:10} "
              f"name={el.get_attribute('name')!r:25} "
              f"id={el.get_attribute('id')!r:25} "
              f"value={el.get_attribute('value')!r:20} "
              f"placeholder={el.get_attribute('placeholder')!r}")
    print(f"  [DEBUG] ── All textareas ──")
    for el in driver.find_elements(By.TAG_NAME, "textarea"):
        print(f"    name={el.get_attribute('name')!r:25} "
              f"id={el.get_attribute('id')!r:25} "
              f"placeholder={el.get_attribute('placeholder')!r}")
    print(f"  [DEBUG] ── All buttons ──")
    for el in driver.find_elements(By.TAG_NAME, "button"):
        print(f"    type={el.get_attribute('type')!r:10} "
              f"text={el.text!r:20} "
              f"class={el.get_attribute('class')!r}")
    print()


# ─── Cookie banner ────────────────────────────────────────────────────────────

def _dismiss_cookies(driver):
    """Accept cookie consent banner if it appears."""
    selectors = [
        "button[id*='accept' i]",
        "button[class*='accept' i]",
        "a[id*='accept' i]",
        ".cookie-accept",
        "#cookie-accept",
        "button:contains('Accept')",   # jQuery-style, won't work in Selenium — handled below
    ]
    # Try text-based search for Accept buttons
    for btn in driver.find_elements(By.TAG_NAME, "button"):
        txt = (btn.text or "").strip().lower()
        if "accept" in txt and btn.is_displayed():
            try:
                btn.click()
                print(f"  [APPEAL] 🍪  Cookie banner dismissed.")
                time.sleep(1)
                return
            except Exception:
                pass
    # Try CSS selectors
    for sel in selectors[:4]:
        el = _safe_find(driver, sel)
        if el:
            try:
                el.click()
                print(f"  [APPEAL] 🍪  Cookie banner dismissed.")
                time.sleep(1)
                return
            except Exception:
                pass


# ─── Core fill logic ──────────────────────────────────────────────────────────

def _fill_form(driver, domain: str, flagged_by: Dict[str, str], debug: bool) -> bool:
    wait = WebDriverWait(driver, 25)

    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    # Wait for page to load
    try:
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "form")))
        time.sleep(3)
    except TimeoutException:
        print(f"  [APPEAL] ❌  Page did not load in time.")
        return False

    # Dismiss cookie banner if present
    _dismiss_cookies(driver)

    if debug:
        print(f"  [DEBUG] Title: {driver.title}")
        _print_all_fields(driver)

    # ── Step 1: Select the radio button if it exists ──────────────────────────
    print(f"  [APPEAL] 🔘  Checking for radio: form_type = '{RADIO_VALUE}'...")
    radio = _safe_find(
        driver,
        f"input[type='radio'][name='form_type'][value='{RADIO_VALUE}']"
    )
    if not radio:
        # Fallback: find by value only
        radio = _safe_find(driver, f"input[value='{RADIO_VALUE}']")

    if radio:
        _safe_click(driver, radio)
        print(f"  [APPEAL] ✅  Radio button selected.")
        time.sleep(2)   # wait for the sub-form to reveal itself
    else:
        print(f"  [APPEAL] ℹ️   Radio button (form_type='{RADIO_VALUE}') not found — continuing without selection.")

    if debug:
        print(f"  [DEBUG] Fields after radio selection:")
        _print_all_fields(driver)

    # ── Step 2: Fill fields ───────────────────────────────────────────────────
    url_with_scheme  = _ensure_scheme(domain)
    sender_name      = TEMPLATE.get("requestor_name",
                                     TEMPLATE.get("company_name", "BK8 Support"))
    sender_email     = TEMPLATE["requestor_email"]
    company          = TEMPLATE.get("company_name", "BK8 Support")
    subject          = _build_subject(domain)
    body             = _build_body(domain, flagged_by)

    # Field definitions: (label, css_selectors_to_try, value_to_fill)
    # Ordered by most-likely selector first based on typical Lionic/custom form patterns
    fields = [
        ("URL",     [
            "input[name='url']",
            "input[name='fp_url']",
            "input[name='vt_url']",
            "input[placeholder*='URL' i]",
            "input[placeholder*='url' i]",
            "input[placeholder*='http' i]",
        ], url_with_scheme),

        ("Subject", [
            "input[name='subject']",
            "input[name='title']",
            "input[placeholder*='subject' i]",
            "input[placeholder*='Subject' i]",
        ], subject),

        ("Name",    [
            "input[name='name']",
            "input[name='your-name']",
            "input[name='contact_name']",
            "input[name='user_name']",
            "input[placeholder*='name' i]",
            "input[placeholder*='Name' i]",
        ], sender_name),

        ("Email",   [
            "input[name='email']",
            "input[name='your-email']",
            "input[name='contact_email']",
            "input[name='user_email']",
            "input[type='email']",
            "input[placeholder*='email' i]",
        ], sender_email),

        ("Company", [
            "input[name='company']",
            "input[name='organisation']",
            "input[name='organization']",
            "input[placeholder*='company' i]",
            "input[placeholder*='organisation' i]",
        ], company),

        ("Comments / Message", [
            "textarea[name='message']",
            "textarea[name='comment']",
            "textarea[name='comments']",
            "textarea[name='description']",
            "textarea[name='reason']",
            "textarea[name='content']",
            "textarea",
        ], body),
    ]

    filled_any = False
    for label, selectors, value in fields:
        el = None
        for sel in selectors:
            el = _safe_find(driver, sel)
            if el:
                break
        if el:
            try:
                el.clear()
                el.send_keys(value)
                display_val = value if len(value) <= 60 else f"({len(value)} chars)"
                print(f"  [APPEAL] ✏️   {label:<22}: {display_val}")
                filled_any = True
            except Exception as e:
                print(f"  [APPEAL] ⚠️   Could not fill {label}: {e}")
        else:
            # URL, Email, and Subject are critical — warn loudly
            if label in ("URL", "Email", "Subject"):
                print(f"  [APPEAL] ⚠️   {label} field not found — may affect submission.")
            else:
                print(f"  [APPEAL] ℹ️   {label} field not found (may not exist in this form).")

    if not filled_any:
        print(f"  [APPEAL] ❌  No fields could be filled. Run with debug=True.")
        return False

    # ── Step 3: Check privacy policy checkbox ────────────────────────────────
    print(f"  [APPEAL] ☑️   Checking privacy policy checkbox...")
    privacy_checkbox = _safe_find(driver, "input[name='policy_allowed']")
    if privacy_checkbox:
        if not privacy_checkbox.is_selected():
            _safe_click(driver, privacy_checkbox)
            print(f"  [APPEAL] ✅  Privacy policy checkbox checked.")
        else:
            print(f"  [APPEAL] ℹ️   Privacy policy checkbox already checked.")
    else:
        print(f"  [APPEAL] ⚠️   Privacy policy checkbox not found — may affect submission.")

    # ── Step 4: Auto-click submit ─────────────────────────────────────────────
    # Lionic has no CAPTCHA — submit button can be clicked automatically.
    # Prefer "Submit Only" button over "Submit and Subscribe"
    submit_btn = None
    # First, try to find "Submit Only" button
    for btn in driver.find_elements(By.TAG_NAME, "button"):
        if "submit only" in btn.text.lower().strip():
            submit_btn = btn
            break
    for inp in driver.find_elements(By.TAG_NAME, "input"):
        if inp.get_attribute("type") == "submit" and "submit only" in (inp.get_attribute("value") or "").lower():
            submit_btn = inp
            break
    
    # Fallback to any submit button
    if not submit_btn:
        submit_btn = (
            _safe_find(driver, "button[type='submit']") or
            _safe_find(driver, "input[type='submit']") or
            _safe_find(driver, "button.btn-primary") or
            _safe_find(driver, "button.submit")
        )
    if not submit_btn:
        print(f"  [APPEAL] ❌  Submit button not found — aborting.")
        return False

    print(f"  [APPEAL] 🖱️   Clicking submit automatically...")
    initial_url = driver.current_url
    _safe_click(driver, submit_btn)

    # ── Step 4: Detect success ────────────────────────────────────────────────
    print(f"  [APPEAL] ⏳  Waiting for success response...")

    end_time = time.time() + 20
    while time.time() < end_time:
        time.sleep(1)

        current_url = driver.current_url
        if current_url != initial_url:
            if any(kw in current_url.lower() for kw in ("thank", "success", "sent", "complete")):
                print(f"  [APPEAL] ✅  Redirected to success page: {current_url}")
                return True
            print(f"  [APPEAL] ✅  Page navigated after submission: {current_url}")
            return True

        try:
            body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            if any(kw in body_text for kw in (
                "thank you", "successfully", "has been submitted",
                "received your", "we will review", "submission received"
            )):
                print(f"  [APPEAL] ✅  Success message detected on page.")
                return True
            if any(kw in body_text for kw in ("error occurred", "failed to send", "please try again")):
                print(f"  [APPEAL] ❌  Error message on page — submission failed.")
                return False
        except Exception:
            pass

        for sel in (".alert-success", ".success-message", "#success",
                    ".form-success", "[class*='success' i]", "[class*='thank' i]"):
            try:
                el = driver.find_element(By.CSS_SELECTOR, sel)
                if el.is_displayed() and el.text.strip():
                    print(f"  [APPEAL] ✅  Success element: {el.text.strip()[:100]}")
                    return True
            except Exception:
                pass

    print(f"  [APPEAL] ⚠️   No success signal after 20s.")
    return False


# ─── Main entry ───────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: Dict[str, str], headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a false positive report to Lionic via their web form.

    Selects the AntiVirus-VT radio button, fills all fields automatically,
    auto-clicks Submit (Lionic has no CAPTCHA).

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Ignored — always runs visible so user can click Submit.
        debug      : Print all page fields for troubleshooting.

    Returns:
        True if success detected, False on failure or timeout.
    """
    global _shared_driver

    domain     = _clean_domain(url)
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── Lionic (Selenium / auto-submit) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill + Auto-submit")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()
            own_driver = True

        ok = _fill_form(driver, domain, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
            time.sleep(3)   # let user see the success page before browser closes
        else:
            print(f"  [APPEAL] ❌  Failed or timed out for: {domain}")

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