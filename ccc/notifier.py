"""Google Chat webhook notifier.

Uses Incoming Webhook URL from a Chat space (NOT an Apps Script bot URL).
Payload shape: plain text message with monospace fences for the metadata
table. Format mirrors a CERT/CC or vendor advisory - no decorative content.

Docs:
  https://developers.google.com/workspace/chat/format-messages

--dry-run prints the exact text body to stdout and sends nothing.
"""
from __future__ import annotations

import json
from html import escape as _esc
from typing import Any

import httpx

from ccc import cwe
from ccc.matcher import Match


class NotifyError(Exception):
    """Webhook delivery failed - caller should exit 3 and not advance last_run."""


# ---------- public API ----------

def send_alert(
    webhook_url: str,
    match: Match,
    is_update: bool,
    dry_run: bool = False,
    timeout: float = 15.0,
) -> None:
    """Send one alert. Raises NotifyError on delivery failure."""
    payload = _build_payload(match, is_update)
    if dry_run:
        # Payload uses cardsV2 (no top-level text). Print a readable rendering
        # of the card text so operators can review without sending.
        print(_dry_run_render(match, is_update))
        return
    _post(webhook_url, payload, timeout)


def _dry_run_render(match: Match, is_update: bool) -> str:
    """Best-effort plain-text rendering of the card for --dry-run."""
    cve = match.cve
    sev = (cve.cvss_severity or "Unknown").capitalize()
    cvss_score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    epss = f"{match.epss * 100:.1f}%" if match.epss is not None else "n/a"
    kev = "Yes (CISA actively exploited)" if match.kev else "No"
    upd = " [UPDATED]" if is_update else ""
    title = _derive_title(match)
    products = ", ".join(p.name for p in match.products)
    lines = [
        f"{cve.cve_id}{upd}: {title}",
        "",
        f"Product:  {products}",
        f"CVSS:     {cvss_score} {sev} / {cve.cvss_vector or 'n/a'}",
        f"Status:   {cve.vuln_status}",
        f"EPSS:     {epss}",
        f"KEV:      {kev}",
        f"Advisory: {cve.nvd_url}",
    ]
    return "\n".join(lines)


def send_test(webhook_url: str, dry_run: bool = False, timeout: float = 15.0) -> None:
    """Send a plain webhook verification message."""
    payload = {"text": "ccc: webhook reachable. Future alerts will be CVE advisories."}
    if dry_run:
        print("DRY RUN: would POST")
        print(json.dumps(payload, indent=2))
        return
    _post(webhook_url, payload, timeout)


# ---------- card builder ----------
#
# Output: cardsV2 message with decoratedText widgets, one per row.
# Top-level `text` field is the notification preview (mobile push, channel
# list, plain-text fallback). The card is the rich body.
#
# Verified against official docs at developers.google.com/workspace/chat:
# - `text` field: Hangouts-style *bold* / _italic_ / ~strike~ / `code`, no HTML.
#   Plain URLs auto-link. Labeled links: <https://url|label>.
# - cardsV2 decoratedText.text: supports HTML subset including <font color>
#   and <b>. topLabel/bottomLabel are PLAIN STRINGS only (no HTML).
# - materialIcon: any Material Symbols name (warning, bug_report, shield, etc.)
# - knownIcon: enum of 28 values, none security-relevant - don't use.

SEVERITY_COLOR = {
    "CRITICAL": "#cc0000",   # red
    "HIGH":     "#e67e22",   # orange
    "MEDIUM":   "#d4ac0d",   # amber
    "LOW":      "#2e86c1",   # blue
    "NONE":     "#7f8c8d",
    "UNKNOWN":  "#7f8c8d",
}


# CWE short-name table moved to ccc/cwe.py so the notifier stays focused
# on formatting + transport. Lookup via cwe.lookup(cwe_id).


def _derive_title(match: "Match", max_len: int = 120) -> str:
    """Resolve a clean human title in priority order:

      1. CISA KEV vulnerabilityName (curated, short, definitive)
      2. CWE short name + product (structured class of bug)
      3. First sentence of NVD description (fallback)

    Zero extra HTTP calls - both KEV and CWE come from data already fetched.
    """
    # 1. KEV-curated name (best signal when present)
    if match.kev_name:
        return _truncate(match.kev_name, max_len)

    # 2. CWE name + product (good for non-KEV CVEs with a known weakness class)
    cve = match.cve
    for cwe_id in cve.cwes:
        name = cwe.lookup(cwe_id)
        if name:
            product = match.products[0].name if match.products else ""
            return _truncate(f"{name} in {product}" if product else name, max_len)

    # 3. First sentence of description (last resort)
    description = cve.description or ""
    if not description:
        return "(no title)"
    text = description.strip().replace("\n", " ")
    end = text.find(". ")
    if 0 < end <= max_len:
        return text[:end]
    return _truncate(text, max_len)


def _truncate(s: str, max_len: int) -> str:
    if len(s) > max_len:
        return s[:max_len - 1].rstrip() + "\u2026"
    return s


def _build_payload(match: Match, is_update: bool) -> dict[str, Any]:
    """Build the Google Chat cardsV2 payload.

    SECURITY: NVD descriptions are vendor-supplied free text. KEV names come
    from CISA but pass through here too. Product names come from operator
    YAML. EVERY interpolated value is run through html.escape so a malicious
    description cannot break out of the textParagraph and inject HTML/links.
    Only our static <b>/<font>/<br>/<a href=our-NVD-URL> tags are raw.
    """
    cve = match.cve
    sev_key = (cve.cvss_severity or "UNKNOWN").upper()
    sev = (cve.cvss_severity or "Unknown").capitalize()
    color = SEVERITY_COLOR.get(sev_key, SEVERITY_COLOR["UNKNOWN"])

    cvss_score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    epss_value = f"{match.epss * 100:.1f}%" if match.epss is not None else "n/a"

    # All values escaped before they touch the HTML body.
    cve_id_e   = _esc(cve.cve_id)
    title_e    = _esc(_derive_title(match))
    products_e = _esc(", ".join(p.name for p in match.products))
    status_e   = _esc(cve.vuln_status)
    vector_e   = _esc(cve.cvss_vector or "n/a")
    sev_e      = _esc(sev)
    color_e    = _esc(color)
    # NVD URL is built by us (f"https://nvd.nist.gov/vuln/detail/{cve_id}");
    # escape defensively in case cve_id ever has weird chars.
    nvd_url_e  = _esc(cve.nvd_url, quote=True)

    kev_value = (
        f"<font color=\"#cc0000\"><b>Yes</b></font> (CISA actively exploited)"
        if match.kev else "No"
    )

    sev_colored = f"<font color=\"{color_e}\"><b>{sev_e}</b></font>"
    updated_tag = " <b>[UPDATED]</b>" if is_update else ""

    body = (
        f"<b>{cve_id_e}</b>{updated_tag}: {title_e}"
        f"<br><br>"
        f"<b>Product:</b> {products_e}<br>"
        f"<b>CVSS:</b> {cvss_score} {sev_colored} / {vector_e}<br>"
        f"<b>Status:</b> {status_e}<br>"
        f"<b>EPSS:</b> {epss_value}<br>"
        f"<b>KEV:</b> {kev_value}<br>"
        f"<b>Advisory:</b> <a href=\"{nvd_url_e}\">{nvd_url_e}</a>"
    )

    widgets = [{"textParagraph": {"text": body}}]

    return {
        "cardsV2": [
            {
                "cardId": cve.cve_id,
                "card": {
                    "sections": [{"widgets": widgets}],
                },
            }
        ],
    }


# ---------- transport ----------

def _post(url: str, payload: dict[str, Any], timeout: float) -> None:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
    except httpx.HTTPError as e:
        raise NotifyError(f"webhook request failed: {e}") from e

    if resp.status_code >= 400:
        raise NotifyError(
            f"webhook HTTP {resp.status_code}: {resp.text[:300]}"
        )



