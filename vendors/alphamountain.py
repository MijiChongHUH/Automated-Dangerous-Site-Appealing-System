"""
vendors/alphamountain.py
========================
Playwright automation for alphaMountain.ai false positive submission.
Form URL: https://www.alphamountain.ai/false-positive/

The form is a Freshdesk embedded widget iframe.
Freshdesk field names follow this pattern inside the iframe:
  - Email    : input[name="helpdesk_ticket[requester]"]
  - Subject  : input[name="helpdesk_ticket[subject]"]
  - Body     : textarea[name="helpdesk_ticket[description]"]
  - Custom   : input/select[name="helpdesk_ticket[custom_field][cf_XXXX]"]

Since we don't know the exact cf_ key for "Disputed Website" and "Category",
the script uses a debug dump on first run to print ALL field names found in
the iframe — so we can identify the exact selectors.

Vendor name in VirusTotal: "alphaMountain.ai"
"""

import json
from datetime import datetime
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
except ImportError:
    print("[ERROR] Playwright not installed. Run: pip install playwright && playwright install chromium")
    raise


FORM_URL    = "https://www.alphamountain.ai/false-positive/"
VENDOR_NAME = "alphaMountain.ai"
TEMPLATE    = json.loads(Path("template.json").read_text())

# ── Known Freshdesk field names (standard) ───────────────────────────────────
SEL_EMAIL            = 'input[name="helpdesk_ticket[requester]"]'
SEL_NAME             = 'input[name="helpdesk_ticket[name]"]'
SEL_SUBJECT          = 'input[name="helpdesk_ticket[subject]"]'
SEL_BODY             = 'textarea[name="helpdesk_ticket[description]"]'

# ── Custom fields — these cf_ keys are unique per Freshdesk account.
# Run once with DEBUG_FIELDS=True below to print all field names,
# then update these selectors with the real cf_ key you see printed.
SEL_DISPUTED_WEBSITE = 'input[name="helpdesk_ticket[custom_field][cf_website_1555433]"]'
SEL_CATEGORY         = 'select[name="helpdesk_ticket[custom_field][cf_suggested_category_1555433]"]'


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


def _debug_dump_fields(frame):
    """Print all input/select/textarea names found inside the iframe for debugging."""
    print("\n  [DEBUG] ── All fields found inside Freshdesk iframe ──")
    els = frame.query_selector_all("input, textarea, select")
    for el in els:
        name  = el.get_attribute("name")  or ""
        id_   = el.get_attribute("id")    or ""
        type_ = el.get_attribute("type")  or el.evaluate("el => el.tagName.toLowerCase()")
        if name or id_:
            print(f"  [DEBUG]   tag={type_:<10} name={name:<60} id={id_}")
    print("  [DEBUG] ── End of field dump ──\n")


def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Open the alphaMountain false positive form, switch into the Freshdesk
    iframe, fill all fields, then pause for the user to solve reCAPTCHA
    and click Submit.

    Set debug=True (default) to print all field names on first run.
    Once you know the exact cf_ field names, set debug=False.
    """
    domain = _clean_domain(url)
    fields = _build_fields(domain, flagged_by)

    print(f"\n  [APPEAL] Opening alphaMountain false positive form...")
    print(f"  [APPEAL] Domain  : {domain}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, slow_mo=400)
            context = browser.new_context()
            page    = context.new_page()

            # ── Navigate ──────────────────────────────────────────────────────
            # Use domcontentloaded instead of networkidle — faster and more reliable
            page.goto(FORM_URL, wait_until="domcontentloaded", timeout=30000)
            print(f"  [APPEAL] Page loaded. Locating Freshdesk iframe...")

            # ── Find iframe ───────────────────────────────────────────────────
            # Give the page extra time to inject the Freshdesk iframe via JS
            page.wait_for_selector("iframe", timeout=15000)
            frame = None

            for iframe_el in page.query_selector_all("iframe"):
                src = iframe_el.get_attribute("src") or ""
                if any(kw in src for kw in ["freshdesk", "freshservice", "freshworks", "feedback_widget"]):
                    frame = iframe_el.content_frame()
                    print(f"  [APPEAL] Found iframe: {src[:90]}")
                    break

            if frame is None and len(page.frames) > 1:
                frame = page.frames[1]
                print(f"  [APPEAL] Using fallback iframe.")

            if frame is None:
                print(f"  [APPEAL] ERROR: No iframe found.")
                browser.close()
                return False

            # Wait for iframe content — use longer timeout, Freshdesk can be slow
            print(f"  [APPEAL] Waiting for iframe fields to render...")
            try:
                frame.wait_for_load_state("domcontentloaded", timeout=15000)
            except Exception:
                pass  # continue anyway, fields may still be present

            # Try waiting for the email field specifically — most reliable indicator
            try:
                frame.wait_for_selector('input[name="helpdesk_ticket[requester]"]', timeout=15000)
                print(f"  [APPEAL] Iframe fields ready.")
            except Exception:
                # Fields not found with known selector — still try and let debug dump show what's there
                print(f"  [APPEAL] Could not confirm fields loaded — proceeding anyway...")

            # ── Debug dump — prints all field names so we can find cf_ keys ──
            if debug:
                _debug_dump_fields(frame)

            # ── Fill: Email ───────────────────────────────────────────────────
            _fill(frame, SEL_EMAIL, fields["email"], "Email")

            # ── Fill: Name ────────────────────────────────────────────────────
            _fill(frame, SEL_NAME, fields["name"], "Name")

            # ── Fill: Subject ─────────────────────────────────────────────────
            _fill(frame, SEL_SUBJECT, fields["subject"], "Subject")

            # ── Fill: Body ────────────────────────────────────────────────────
            _fill(frame, SEL_BODY, fields["body"], "Body/Description")

            # ── Fill: Disputed Website ────────────────────────────────────────
            # If WARNING shows here, check the DEBUG dump above for the real
            # cf_ field name and update SEL_DISPUTED_WEBSITE at the top of file
            _fill(frame, SEL_DISPUTED_WEBSITE, fields["domain"], "Disputed Website")

            # ── Select: Category ──────────────────────────────────────────────
            # If WARNING shows here, check the DEBUG dump above for the real
            # cf_ field name and update SEL_CATEGORY at the top of file
            _select(frame, SEL_CATEGORY, fields["category"], "Category")

            # ── Pause for user ────────────────────────────────────────────────
            print(f"\n  {'─'*56}")
            print(f"  [APPEAL] ✅ Filled what we could for: {domain}")
            print(f"  [APPEAL] 👉 Please in the browser window:")
            print(f"  [APPEAL]    1. Fix any fields that show WARNING above")
            print(f"  [APPEAL]    2. Solve the reCAPTCHA")
            print(f"  [APPEAL]    3. Click Submit")
            print(f"  [APPEAL] Then press Enter here to continue.")
            print(f"  {'─'*56}")

            input()

            browser.close()
            print(f"  [APPEAL] Done. Moving on...")
            return True

    except PlaywrightTimeout:
        print(f"  [APPEAL] ERROR: Page timed out.")
        return False
    except Exception as e:
        print(f"  [APPEAL] ERROR: {e}")
        return False


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _fill(frame, selector: str, value: str, label: str):
    """Fill a single field by selector inside the iframe."""
    try:
        el = frame.wait_for_selector(selector, timeout=4000, state="visible")
        if el:
            el.click()
            el.fill(value)
            print(f"  [APPEAL] Filled  : {label}")
            return
    except Exception:
        pass
    print(f"  [APPEAL] WARNING : Could not find '{label}' — fill manually in browser")
    print(f"           Selector tried: {selector}")


def _select(frame, selector: str, label: str, field_label: str):
    """Select a dropdown option by label text inside the iframe."""
    # selector may be comma-separated — try each
    for sel in [s.strip() for s in selector.split(",")]:
        try:
            el = frame.wait_for_selector(sel, timeout=3000, state="visible")
            if el:
                try:
                    frame.select_option(sel, label=label)
                    print(f"  [APPEAL] Selected: {field_label} → {label}")
                    return
                except Exception:
                    pass
                try:
                    frame.select_option(sel, value=label)
                    print(f"  [APPEAL] Selected: {field_label} → {label}")
                    return
                except Exception:
                    pass
        except Exception:
            continue
    print(f"  [APPEAL] WARNING : Could not select '{field_label}' → {label} — select manually")
    print(f"           Selector tried: {selector}")