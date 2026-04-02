"""
vendors/alphamountain.py
========================
Selenium automation for alphaMountain.ai false positive submission.
Form URL: https://www.alphamountain.ai/false-positive/

Root cause of description field failure
────────────────────────────────────────
The form is served inside a Freshdesk iframe (alphamountain.freshdesk.com).
Freshdesk uses Redactor.js as its rich-text editor. Redactor's init sequence:

  1. Hides the original <textarea>
  2. Injects  div.redactor-box
               ├─ ul.redactor-toolbar
               └─ div[contenteditable="true"]   ← actual editor
  3. Places a <p><br></p> placeholder inside the contenteditable div

If we write to the contenteditable div with JS (innerHTML / innerText /
execCommand) BEFORE Redactor finishes step 3, Redactor's own init immediately
overwrites our content with its placeholder.

Even if we write AFTER, Redactor's submit handler reads from its internal
model (not from the DOM) unless typing events are fired in the correct order.

Solution: wait for Redactor to finish init (the <p> placeholder appears),
then use Selenium ActionChains to CLICK the editor and TYPE the text
character by character. This is identical to a real user typing and Redactor
handles it perfectly — no JS injection needed for the body field.

Field map
─────────
  Email    → input[type="email"]
  Name     → helpdesk_ticket[name]
  Subject  → helpdesk_ticket[subject]
  Body     → div[contenteditable="true"]  — filled by ActionChains typing
  Website  → helpdesk_ticket[custom_field][cf_website_1555433]
  Category → helpdesk_ticket[custom_field][cf_suggested_category_1555433]

Dependencies
────────────
  pip install selenium webdriver-manager
  pip install pyperclip          # optional but recommended as fallback
  # Linux only: sudo apt install xclip   (needed by pyperclip)

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
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.keys import Keys
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
    (By.CSS_SELECTOR, 'input[placeholder*="mail"]'),
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

# Redactor contenteditable — the VISIBLE editor div (not the hidden textarea)
SEL_BODY_CE = [
    (By.CSS_SELECTOR, 'div.redactor-box > div[contenteditable="true"]'),
    (By.CSS_SELECTOR, 'div.redactor-box [contenteditable="true"]'),
    (By.CSS_SELECTOR, 'div[contenteditable="true"]'),
]

# Hidden textarea — used ONLY as a last-resort fallback
SEL_BODY_TEXTAREA = [
    (By.ID,           'helpdesk_ticket_ticket_body_attributes_description_html'),
    (By.CSS_SELECTOR, 'textarea[id*="description_html"]'),
    (By.CSS_SELECTOR, 'textarea[id*="body_attributes"]'),
    (By.NAME,         'helpdesk_ticket[description]'),
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


# ─── JS snippets (for non-Redactor fields only) ───────────────────────────────

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
    """Dump all interactive fields in the current frame. Pass debug=True to activate."""
    print("\n  [DEBUG] ── All fields in current frame ──")
    els = driver.find_elements(
        By.CSS_SELECTOR,
        "input, textarea, select, div[contenteditable]"
    )
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
    """Try each (By, selector) in order; return the first element present in DOM."""
    for by, sel in selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((by, sel))
            )
            return el, (by, sel)
        except (TimeoutException, Exception):
            continue
    return None, None


def _fill(driver, selectors: list, value: str, label: str):
    """Fill a regular input or textarea using JS property setter + event dispatch."""
    el, matched = _find_element(driver, selectors, timeout=8)

    if el is None:
        print(f"  [APPEAL] WARNING : '{label}' not found — fill manually")
        for by, sel in selectors:
            print(f"             ({by}) {sel}")
        return

    tag = el.tag_name.lower()
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(0.15)

        if tag == "textarea":
            driver.execute_script(_JS_SET_TEXTAREA, el, value)
        else:
            driver.execute_script(_JS_SET_INPUT, el, value)

        actual = driver.execute_script("return arguments[0].value || '';", el)
        if value[:20] in actual:
            print(f"  [APPEAL] Filled  : {label}  (selector: {matched[1]})")
        else:
            print(f"  [APPEAL] WARNING : '{label}' may not have stuck — check browser")

    except Exception as e:
        print(f"  [APPEAL] WARNING : JS fill failed for '{label}': {e}")


def _select(driver, selectors: list, value: str, field_label: str):
    """Select a dropdown option by visible text, value attr, or JS partial match."""
    el, matched = _find_element(driver, selectors, timeout=8)

    if el is None:
        print(f"  [APPEAL] WARNING : Dropdown '{field_label}' not found — select manually")
        for by, sel in selectors:
            print(f"             ({by}) {sel}")
        return

    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(0.15)
        select = Select(el)

        for method, fn in [
            ("text",  lambda: select.select_by_visible_text(value)),
            ("value", lambda: select.select_by_value(value)),
        ]:
            try:
                fn()
                print(f"  [APPEAL] Selected: {field_label} → {value}  (by {method}, selector: {matched[1]})")
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
        else:
            print(f"  [APPEAL] WARNING : No option matched '{value}' for '{field_label}'")

    except Exception as e:
        print(f"  [APPEAL] WARNING : Dropdown error for '{field_label}': {e}")


def _wait_for_redactor_ready(driver, timeout: int = 30) -> bool:
    """
    Wait until Redactor.js has fully initialised inside the iframe.

    Redactor is considered ready when the contenteditable div exists AND
    contains at least one child element. Redactor injects <p><br></p> as
    its empty placeholder — a completely empty div means init hasn't run yet.
    Writing before init is complete causes Redactor to wipe our content.
    """
    print(f"  [APPEAL] Waiting for Redactor editor to initialise...")
    deadline = time.time() + timeout

    while time.time() < deadline:
        divs = driver.find_elements(By.CSS_SELECTOR, "div[contenteditable='true']")
        if divs:
            child_count = driver.execute_script(
                "return arguments[0].children.length;", divs[0]
            )
            if child_count and int(child_count) > 0:
                print(f"  [APPEAL] Redactor ready (editor has {child_count} child element(s)).")
                time.sleep(0.5)   # let any post-init JS settle
                return True
        time.sleep(0.4)

    print(f"  [APPEAL] Redactor ready-check timed out — proceeding anyway.")
    return False


def _fill_redactor_body(driver, value: str):
    """
    Fill the Redactor.js description field using ActionChains keyboard typing.

    Why ActionChains instead of JS injection
    ─────────────────────────────────────────
    Redactor maintains an internal JS model that is only updated through
    keyboard events fired in the correct browser sequence.  JS writes to
    innerHTML / innerText update the DOM but NOT the internal model, so the
    text appears visually but is wiped or ignored when the form is submitted.

    Typing via ActionChains replicates real keystrokes; Redactor processes
    each character through its own keydown/keyup handlers and keeps its
    internal model in sync automatically.

    Flow
    ────
      1. Wait for Redactor to finish init (polls for <p> child in editor div)
      2. Click the editor to give it browser focus and activate Redactor
      3. Ctrl+A then Delete to clear the <p><br> placeholder
      4. Type text via ActionChains; \n becomes Shift+Enter (soft line break)
      5. Verify content via innerText
      6. If typing produced no content → fall back to clipboard paste (pyperclip)
    """
    label = "Body/Description"

    # Step 1 — wait for Redactor init
    _wait_for_redactor_ready(driver, timeout=30)

    ce_el, ce_matched = _find_element(driver, SEL_BODY_CE, timeout=10)

    if ce_el is None:
        print(f"  [APPEAL] WARNING : Redactor contenteditable not found.")
        print(f"           Trying hidden textarea fallback...")
        _fill(driver, SEL_BODY_TEXTAREA, value, f"{label} (textarea fallback)")
        return

    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", ce_el)
        time.sleep(0.3)

        # Step 2 — click to activate
        ActionChains(driver).click(ce_el).perform()
        time.sleep(0.3)

        # Step 3 — clear placeholder
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
        time.sleep(0.1)
        ActionChains(driver).send_keys(Keys.DELETE).perform()
        time.sleep(0.2)

        # Step 4 — type text, \n → Shift+Enter
        print(f"  [APPEAL] Typing description ({len(value)} chars)...")
        lines  = value.split("\n")
        chain  = ActionChains(driver)
        for i, line in enumerate(lines):
            if line:
                chain.send_keys(line)
            if i < len(lines) - 1:
                chain.key_down(Keys.SHIFT).send_keys(Keys.ENTER).key_up(Keys.SHIFT)
        chain.perform()
        time.sleep(0.5)

        # Step 5 — verify
        actual = driver.execute_script(
            "return arguments[0].innerText || arguments[0].textContent || '';",
            ce_el
        )
        if value[:15] in actual:
            print(f"  [APPEAL] Filled  : {label}  (ActionChains, selector: {ce_matched[1]})")
            print(f"           Preview : {actual[:70].strip()!r}...")
        else:
            print(f"  [APPEAL] WARNING : Typing result inconclusive.")
            print(f"           Expected start : {value[:30]!r}")
            print(f"           Got            : {actual[:50]!r}")
            print(f"           Trying clipboard paste fallback...")
            _fill_redactor_clipboard(driver, ce_el, ce_matched, value, label)

    except Exception as e:
        print(f"  [APPEAL] ERROR in ActionChains body fill: {e}")
        print(f"           Trying clipboard paste fallback...")
        _fill_redactor_clipboard(driver, ce_el, ce_matched, value, label)


def _fill_redactor_clipboard(driver, ce_el, ce_matched, value: str, label: str):
    """
    Clipboard-paste fallback for Redactor.

    Copies text to the OS clipboard via pyperclip, then sends Ctrl+V to the
    editor. Works on Windows/macOS/Linux (Linux requires xclip: apt install xclip).
    Falls back to the hidden textarea if pyperclip is not installed.
    """
    try:
        import pyperclip
        pyperclip.copy(value)

        ActionChains(driver).click(ce_el).perform()
        time.sleep(0.2)
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
        time.sleep(0.1)
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('v').key_up(Keys.CONTROL).perform()
        time.sleep(0.5)

        actual = driver.execute_script("return arguments[0].innerText || '';", ce_el)
        if value[:15] in actual:
            print(f"  [APPEAL] Filled  : {label}  (clipboard paste, selector: {ce_matched[1]})")
        else:
            print(f"  [APPEAL] WARNING : Clipboard paste inconclusive — check browser.")

    except ImportError:
        print(f"  [APPEAL] pyperclip not installed (pip install pyperclip).")
        print(f"           Trying hidden textarea as last resort...")
        _fill(driver, SEL_BODY_TEXTAREA, value, f"{label} (textarea last-resort)")
    except Exception as e:
        print(f"  [APPEAL] Clipboard fallback failed: {e}")
        print(f"           Please fill the Description field manually.")


def _switch_to_freshdesk_iframe(driver, timeout: int = 20) -> bool:
    """Switch the WebDriver context into the Freshdesk feedback widget iframe."""
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
                    print(f"  [APPEAL] Switched to iframe: {src[:90]}")
                    return True
                except Exception:
                    continue
        time.sleep(0.5)

    iframes = driver.find_elements(By.TAG_NAME, "iframe")
    if iframes:
        try:
            driver.switch_to.frame(iframes[0])
            print(f"  [APPEAL] Using fallback: first iframe on page.")
            return True
        except Exception:
            pass

    return False


# ─── Main submit ──────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Open the alphaMountain false positive form, fill all fields, then pause
    for the user to solve reCAPTCHA and click Submit.

    Args:
        url        : The domain/URL being appealed.
        flagged_by : Dict of { vendor_name: verdict } from VirusTotal.
        headless   : Run Chrome headlessly. NOT recommended — reCAPTCHA and
                     Redactor both behave differently without a real display.
        debug      : Dump all field names inside the iframe to stdout before
                     filling. Helpful for re-confirming selectors if the form
                     layout changes.
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
            print(f"  [APPEAL] ERROR : Could not find Freshdesk iframe — aborting.")
            return False

        try:
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input, textarea"))
            )
        except TimeoutException:
            print(f"  [APPEAL] WARNING : Form fields slow to load — proceeding anyway.")

        if debug:
            _debug_dump_fields(driver)

        # ── Fill standard fields ──────────────────────────────────────────────
        _fill(driver,   SEL_EMAIL,   fields["email"],   "Email")
        _fill(driver,   SEL_NAME,    fields["name"],    "Name")
        _fill(driver,   SEL_SUBJECT, fields["subject"], "Subject")

        # ── Fill Redactor description via ActionChains typing ─────────────────
        _fill_redactor_body(driver, fields["body"])

        # ── Fill remaining fields ─────────────────────────────────────────────
        _fill(driver,   SEL_DISPUTED_WEBSITE, fields["domain"],   "Disputed Website")
        _select(driver, SEL_CATEGORY,         fields["category"], "Category")

        print(f"\n  {'─'*56}")
        print(f"  [APPEAL] ✅  Fields filled for: {domain}")
        print(f"  [APPEAL] 👉  In the browser window please:")
        print(f"  [APPEAL]     1. Confirm all fields look correct")
        print(f"  [APPEAL]     2. Solve the reCAPTCHA")
        print(f"  [APPEAL]     3. Click Submit")
        print(f"  [APPEAL] Press Enter here once submitted to continue.")
        print(f"  {'─'*56}")
        input()

        print(f"  [APPEAL] Done. Moving on...")
        return True

    except Exception as e:
        print(f"  [APPEAL] ERROR : {e}")
        return False

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass