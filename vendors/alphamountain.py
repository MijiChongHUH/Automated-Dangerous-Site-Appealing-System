"""
vendors/alphamountain.py
========================
Selenium automation for alphaMountain.ai false positive submission.
Form URL: https://www.alphamountain.ai/false-positive/

Confirmed field IDs from live form inspection:
  - Email    : input[type="email"]
  - Name     : helpdesk_ticket[name]  (may be hidden — JS injected)
  - Subject  : helpdesk_ticket[subject]
  - Body     : #helpdesk_ticket_ticket_body_attributes_description_html
               (nested body_attributes structure, NOT helpdesk_ticket[description])
  - Website  : helpdesk_ticket[custom_field][cf_website_1555433]
  - Category : helpdesk_ticket[custom_field][cf_suggested_category_1555433]

Install dependencies:
    pip install selenium webdriver-manager

Vendor name in VirusTotal: "alphaMountain.ai"
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait, Select
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException
except ImportError:
    print("[ERROR] Selenium not installed. Run: pip install selenium webdriver-manager")
    raise

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("[ERROR] webdriver-manager not installed. Run: pip install webdriver-manager")
    raise


FORM_URL    = "https://www.alphamountain.ai/false-positive/"
VENDOR_NAME = "alphaMountain.ai"
TEMPLATE    = json.loads(Path("template.json").read_text())

# ── Selectors ─────────────────────────────────────────────────────────────────

SEL_EMAIL = [
    (By.NAME,         'helpdesk_ticket[requester]'),
    (By.ID,           'helpdesk_ticket_requester'),
    (By.CSS_SELECTOR, 'input[type="email"]'),
    (By.CSS_SELECTOR, 'input[placeholder*="Email"]'),
]

SEL_NAME = [
    (By.NAME,         'helpdesk_ticket[name]'),
    (By.ID,           'helpdesk_ticket_name'),
    (By.CSS_SELECTOR, 'input[placeholder*="Name"]'),
    (By.CSS_SELECTOR, 'input[placeholder*="Full name"]'),
]

SEL_SUBJECT = [
    (By.NAME,         'helpdesk_ticket[subject]'),
    (By.ID,           'helpdesk_ticket_subject'),
    (By.CSS_SELECTOR, 'input[placeholder*="Subject"]'),
]

# ── Body: confirmed ID from live form label for="..." attribute ───────────────
SEL_BODY = [
    (By.ID,           'helpdesk_ticket_ticket_body_attributes_description_html'),
    (By.CSS_SELECTOR, '[id*="description_html"]'),
    (By.CSS_SELECTOR, '[id*="body_attributes"]'),
    (By.CSS_SELECTOR, 'div[contenteditable="true"]'),
    (By.NAME,         'helpdesk_ticket[description]'),
    (By.ID,           'helpdesk_ticket_description'),
    (By.CSS_SELECTOR, 'textarea[placeholder*="Description"]'),
]

SEL_DISPUTED_WEBSITE = [
    (By.NAME,         'helpdesk_ticket[custom_field][cf_website_1555433]'),
    (By.CSS_SELECTOR, 'input[name*="cf_website"]'),
    (By.CSS_SELECTOR, 'input[placeholder*="Website"]'),
]

SEL_CATEGORY = [
    (By.NAME,         'helpdesk_ticket[custom_field][cf_suggested_category_1555433]'),
    (By.CSS_SELECTOR, 'select[name*="cf_suggested_category"]'),
    (By.CSS_SELECTOR, 'select[name*="cf_category"]'),
]


# ─── JS injection templates ───────────────────────────────────────────────────

_JS_SET_INPUT = """
    var el = arguments[0], val = arguments[1];
    var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    if (setter) setter.set.call(el, val); else el.value = val;
    el.dispatchEvent(new Event('input',  {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
"""

_JS_SET_TEXTAREA = """
    var el = arguments[0], val = arguments[1];
    var setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
    if (setter) setter.set.call(el, val); else el.value = val;
    el.dispatchEvent(new Event('input',  {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
"""

_JS_SET_CONTENTEDITABLE = """
    var el = arguments[0], val = arguments[1];
    el.focus();
    el.innerText = val;
    el.dispatchEvent(new Event('input',  {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    el.dispatchEvent(new KeyboardEvent('keyup', {bubbles: true}));
"""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _build_fields(domain: str, flagged_by: dict) -> dict:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")

    return {
        "email":    TEMPLATE["requestor_email"],
        "name":     TEMPLATE["company_name"],
        "subject":  TEMPLATE["subject_template"].format(domain=domain),
        "body":     TEMPLATE["body_template"].format(
                        vendor_name    = VENDOR_NAME,
                        domain         = domain,
                        detection_type = detection_str,
                        date_flagged   = date_flagged,
                    ),
        "domain":   domain,
        "category": TEMPLATE["suggested_category"],
    }


def _debug_dump_fields(driver):
    """Dump all field attributes in the current iframe — use debug=True once to verify selectors."""
    print("\n  [DEBUG] ── All fields found inside Freshdesk iframe ──")
    els = driver.find_elements(By.CSS_SELECTOR, "input, textarea, select, div[contenteditable]")
    for el in els:
        name        = el.get_attribute("name")        or ""
        id_         = el.get_attribute("id")          or ""
        type_       = el.get_attribute("type")        or ""
        placeholder = el.get_attribute("placeholder") or ""
        tag         = el.tag_name
        ce          = el.get_attribute("contenteditable") or ""
        display     = driver.execute_script(
            "return window.getComputedStyle(arguments[0]).display;", el
        )
        if name or id_ or placeholder or ce == "true":
            print(
                f"  [DEBUG]   <{tag}> "
                f"type={type_:<8} display={display:<12} "
                f"name={name:<50} "
                f"id={id_:<45} "
                f"placeholder={placeholder!r}"
            )
    print("  [DEBUG] ── End of field dump ──\n")


def _find_element(driver, selectors: list, timeout: int = 8):
    """Try each (By, selector) pair, return first element present in DOM."""
    for by, sel in selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((by, sel))
            )
            return el, (by, sel)
        except TimeoutException:
            continue
        except Exception:
            continue
    return None, None


def _fill(driver, selectors: list, value: str, label: str):
    """
    Fill a field using JS injection — works even when the element is
    hidden, covered by an overlay, or marked not interactable.
    Routes to the correct JS injector based on element tag type.
    """
    el, matched = _find_element(driver, selectors, timeout=8)

    if el is None:
        print(f"  [APPEAL] WARNING : Could not find '{label}' — fill manually in browser")
        print(f"           Selectors tried:")
        for by, sel in selectors:
            print(f"             ({by}) {sel}")
        return

    tag = el.tag_name.lower()
    ce  = el.get_attribute("contenteditable") or ""

    try:
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
        time.sleep(0.15)

        if tag == "div" and ce == "true":
            driver.execute_script(_JS_SET_CONTENTEDITABLE, el, value)
        elif tag == "textarea":
            driver.execute_script(_JS_SET_TEXTAREA, el, value)
        else:
            driver.execute_script(_JS_SET_INPUT, el, value)

        # Verify the value actually landed
        actual = driver.execute_script(
            "return arguments[0].value || arguments[0].innerText || '';", el
        )
        if value[:20] in actual:
            print(f"  [APPEAL] Filled  : {label}  (selector: {matched[1]})")
        else:
            print(f"  [APPEAL] WARNING : Injected '{label}' but value did not stick — fill manually")
            print(f"           Expected start: {value[:40]!r}")
            print(f"           Got           : {actual[:40]!r}")

    except Exception as e:
        print(f"  [APPEAL] WARNING : Found '{label}' but JS injection failed: {e}")


def _select(driver, selectors: list, value: str, field_label: str):
    """Select a dropdown option by text, value attribute, or JS partial match."""
    el, matched = _find_element(driver, selectors, timeout=8)

    if el is None:
        print(f"  [APPEAL] WARNING : Could not find '{field_label}' dropdown — select manually")
        print(f"           Selectors tried:")
        for by, sel in selectors:
            print(f"             ({by}) {sel}")
        return

    try:
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", el)
        time.sleep(0.15)

        select = Select(el)

        try:
            select.select_by_visible_text(value)
            print(f"  [APPEAL] Selected: {field_label} → {value}  (by text, selector: {matched[1]})")
            return
        except Exception:
            pass

        try:
            select.select_by_value(value)
            print(f"  [APPEAL] Selected: {field_label} → {value}  (by value, selector: {matched[1]})")
            return
        except Exception:
            pass

        result = driver.execute_script(
            """
            var el = arguments[0], val = arguments[1].toLowerCase();
            for (var i = 0; i < el.options.length; i++) {
                if (el.options[i].text.toLowerCase().includes(val) ||
                    el.options[i].value.toLowerCase().includes(val)) {
                    el.selectedIndex = i;
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                    return el.options[i].text;
                }
            }
            return null;
            """,
            el, value
        )
        if result:
            print(f"  [APPEAL] Selected: {field_label} → {result}  (JS partial, selector: {matched[1]})")
            return

        print(f"  [APPEAL] WARNING : Found '{field_label}' but no option matched '{value}' — select manually")

    except Exception as e:
        print(f"  [APPEAL] WARNING : Could not interact with '{field_label}' dropdown: {e}")


def _switch_to_freshdesk_iframe(driver, timeout: int = 20) -> bool:
    """Switch into the Freshdesk feedback widget iframe."""
    driver.switch_to.default_content()
    driver.execute_script("window.scrollBy(0, 300);")
    time.sleep(0.5)

    deadline = time.time() + timeout
    while time.time() < deadline:
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        for iframe in iframes:
            src = iframe.get_attribute("src") or ""
            if any(kw in src for kw in ["freshdesk", "freshservice", "freshworks", "feedback_widget"]):
                try:
                    driver.switch_to.frame(iframe)
                    print(f"  [APPEAL] Found iframe: {src[:90]}")
                    return True
                except Exception:
                    continue
        time.sleep(0.5)

    iframes = driver.find_elements(By.TAG_NAME, "iframe")
    if iframes:
        try:
            driver.switch_to.frame(iframes[0])
            print(f"  [APPEAL] Using fallback iframe (first iframe on page).")
            return True
        except Exception:
            pass

    return False


def _wait_for_fields(driver, timeout: int = 20) -> bool:
    """Wait until at least one input or textarea is present in the current frame."""
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input, textarea"))
        )
        return True
    except TimeoutException:
        return False


# ─── Main submit ──────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Open the alphaMountain false positive form, fill all fields via JS injection,
    then pause for the user to solve reCAPTCHA and click Submit.

    Args:
        url        : The domain/URL being appealed.
        flagged_by : Dict of vendor → verdict from VirusTotal.
        headless   : Run browser headlessly (default False).
        debug      : Dump all iframe field names to help confirm selectors.
    """
    domain = _clean_domain(url)
    fields = _build_fields(domain, flagged_by)

    print(f"\n  [APPEAL] Opening alphaMountain false positive form...")
    print(f"  [APPEAL] Domain  : {domain}")

    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    options.add_argument("--window-size=1280,900")

    driver = None
    try:
        service = Service(ChromeDriverManager().install())
        driver  = webdriver.Chrome(service=service, options=options)
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        driver.get(FORM_URL)
        print(f"  [APPEAL] Page loaded. Locating Freshdesk iframe...")

        found = _switch_to_freshdesk_iframe(driver, timeout=20)
        if not found:
            print(f"  [APPEAL] ERROR: Could not find Freshdesk iframe.")
            return False

        print(f"  [APPEAL] Waiting for iframe fields to render...")
        ready = _wait_for_fields(driver, timeout=20)
        if ready:
            print(f"  [APPEAL] Iframe fields ready.")
        else:
            print(f"  [APPEAL] Fields may not be fully loaded — proceeding anyway...")

        time.sleep(2)

        if debug:
            _debug_dump_fields(driver)

        _fill(driver,   SEL_EMAIL,            fields["email"],    "Email")
        _fill(driver,   SEL_NAME,             fields["name"],     "Name")
        _fill(driver,   SEL_SUBJECT,          fields["subject"],  "Subject")
        _fill(driver,   SEL_BODY,             fields["body"],     "Body/Description")
        _fill(driver,   SEL_DISPUTED_WEBSITE, fields["domain"],   "Disputed Website")
        _select(driver, SEL_CATEGORY,         fields["category"], "Category")

        print(f"\n  {'─'*56}")
        print(f"  [APPEAL] ✅ Filled what we could for: {domain}")
        print(f"  [APPEAL] 👉 Please in the browser window:")
        print(f"  [APPEAL]    1. Fix any fields that show WARNING above")
        print(f"  [APPEAL]    2. Solve the reCAPTCHA")
        print(f"  [APPEAL]    3. Click Submit")
        print(f"  [APPEAL] Then press Enter here to continue to the next domain.")
        print(f"  {'─'*56}")
        input()

        print(f"  [APPEAL] Done. Moving on...")
        return True

    except Exception as e:
        print(f"  [APPEAL] ERROR: {e}")
        return False

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass