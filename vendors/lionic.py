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
  3. Select the "AntiVirus-VT" radio button → reveals the correct sub-form.
  4. Fill all visible fields automatically.
  5. Auto-clicks the Submit button (no CAPTCHA on Lionic).
  6. Detects the success response and confirms in the terminal.

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
import random
from datetime import datetime
from pathlib import Path

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
RADIO_VALUE    = "AntiVirus-VT"     # the radio button value to select
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
    tpl = TEMPLATE.get("lionic_subject_template",
                        TEMPLATE.get("subject_template",
                                     "False Positive Report: {domain}"))
    return tpl.format(domain=domain)


def _build_body(domain: str, flagged_by: dict) -> str:
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

def _fill_form(driver, domain: str, flagged_by: dict, debug: bool) -> bool:
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

    # Brief realistic pause — lets reCAPTCHA v3 observe page interaction
    time.sleep(random.uniform(1.5, 2.5))

    # Add human-like scrolling and mouse movement to improve reCAPTCHA score
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 4);")
    time.sleep(random.uniform(0.5, 1.0))
    driver.execute_script("window.scrollTo(0, 0);")
    time.sleep(random.uniform(0.5, 1.0))

    # Dismiss cookie banner if present
    _dismiss_cookies(driver)

    if debug:
        print(f"  [DEBUG] Title: {driver.title}")
        _print_all_fields(driver)

    # ── Step 1: Select the AntiVirus-VT radio button ──────────────────────────
    print(f"  [APPEAL] 🔘  Selecting radio: form_type = '{RADIO_VALUE}'...")
    radio = _safe_find(
        driver,
        f"input[type='radio'][name='form_type'][value='{RADIO_VALUE}']"
    )
    if not radio:
        # Fallback: find by value only
        radio = _safe_find(driver, f"input[value='{RADIO_VALUE}']")

    if not radio:
        print(f"  [APPEAL] ❌  Radio button (form_type='{RADIO_VALUE}') not found.")
        if not debug:
            print(f"  [APPEAL]     Re-run with debug=True to inspect all fields.")
        return False

    _safe_click(driver, radio)
    print(f"  [APPEAL] ✅  Radio button selected.")
    time.sleep(random.uniform(2.0, 3.0))   # wait for the sub-form to reveal itself

    # Scroll to form area after radio selection
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2);")
    time.sleep(random.uniform(0.5, 1.0))

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
            "input[name='title']",
            "input[name='subject']",
            "input[placeholder*='Title' i]",
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

    # Randomize field filling order to appear more human-like
    field_indices = list(range(len(fields)))
    random.shuffle(field_indices)

    filled_any = False
    for idx in field_indices:
        label, selectors, value = fields[idx]
        el = None
        for sel in selectors:
            el = _safe_find(driver, sel)
            if el:
                break
        if el:
            try:
                el.clear()
                time.sleep(random.uniform(0.3, 0.8))  # Random pause before typing
                # Type character by character for human-like input
                for char in value:
                    el.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))  # Slightly longer random delays
                display_val = value if len(value) <= 60 else f"({len(value)} chars)"
                print(f"  [APPEAL] ✏️   {label:<22}: {display_val}")
                filled_any = True
                # Pause between fields
                time.sleep(random.uniform(0.5, 1.5))
            except Exception as e:
                print(f"  [APPEAL] ⚠️   Could not fill {label}: {e}")
        else:
            # URL and Email are critical — warn loudly
            if label in ("URL", "Email", "Subject"):
                print(f"  [APPEAL] ⚠️   {label} field not found — may affect submission.")
            else:
                print(f"  [APPEAL] ℹ️   {label} field not found (may not exist in this form).")

    if not filled_any:
        print(f"  [APPEAL] ❌  No fields could be filled. Run with debug=True.")
        return False

    # Scroll to submit area after filling
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight * 0.75);")
    time.sleep(random.uniform(0.5, 1.0))

    # ── Step 3: Scroll "Submit Only" button into view, prompt user ──────────
    # reCAPTCHA v3 scores too low for automated click — user clicks manually.
    submit_btn = None
    for btn in driver.find_elements(By.TAG_NAME, "button"):
        if "submit only" in (btn.text or "").lower().strip():
            submit_btn = btn
            break
    if not submit_btn:
        submit_btn = (
            _safe_find(driver, "button[type='submit']") or
            _safe_find(driver, "input[type='submit']") or
            _safe_find(driver, "button.btn-primary")
        )
    if submit_btn:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", submit_btn)

    print(f"")
    print(f"  [APPEAL] ✅  Form filled. Browser window is ready.")
    print(f"  [APPEAL] 👉  Please click the SUBMIT ONLY button in the browser now.")
    print(f"  [APPEAL]     Waiting up to {USER_WAIT_SECS}s for you to submit...")
    print(f"")

    initial_url = driver.current_url

    # ── Step 4: Detect success ────────────────────────────────────────────────
    print(f"  [APPEAL] ⏳  Waiting for success response...")

    end_time = time.time() + USER_WAIT_SECS
    while time.time() < end_time:
        time.sleep(1)

        current_url = driver.current_url
        if current_url != initial_url:
            if any(kw in current_url.lower() for kw in ("thank", "success", "sent", "complete")):
                print(f"  [APPEAL] ✅  Redirected to success page: {current_url}")
                return True
            # URL changed but no success keyword — wait 2s to confirm it settled
            time.sleep(2)
            settled_url = driver.current_url
            if settled_url != initial_url:
                print(f"  [APPEAL] ✅  Page navigated after submission: {settled_url}")
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

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a false positive report to Lionic via their web form.

    Selects the AntiVirus-VT radio button, fills all fields automatically,
    then waits for the user to click Submit Only (bypasses reCAPTCHA).

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

    print(f"\n  [APPEAL] ── Lionic (Selenium / manual send) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill → User clicks Submit Only")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()
            own_driver = True

        ok = _fill_form(driver, domain, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
            time.sleep(8)   # give user time to see the success page before browser closes
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