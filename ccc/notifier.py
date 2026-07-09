# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Google Chat webhook notifier.

Uses Incoming Webhook URL from a Chat space (NOT an Apps Script bot URL).
Payload shape: plain text message with monospace fences for the metadata
table. Format mirrors a CERT/CC or vendor advisory - no decorative content.

Docs:
  https://developers.google.com/workspace/chat/format-messages

--dry-run prints the exact text body to stdout and sends nothing.

Batch (digest) mode:
  When a product is configured with alert_mode: batch (in products.yaml),
  CVEs are grouped by product and sent as one digest per run instead of
  one card per CVE. The digest card summarises CVSS range, EPSS range,
  KEV count, and lists each CVE as a hyperlinked advisory.
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


def send_batch_alert(
    webhook_url: str,
    product_name: str,
    matches: list[Match],
    dry_run: bool = False,
    timeout: float = 15.0,
) -> None:
    """Send one batch digest for a product's new CVEs this run.

    Groups all new CVEs for a single product into one cardsV2 message
    with a summary header and a numbered advisory list.
    """
    if not matches:
        return
    payload = _build_batch_payload(product_name, matches)
    if dry_run:
        print(_dry_run_batch_render(product_name, matches))
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


def _dry_run_batch_render(product_name: str, matches: list[Match]) -> str:
    """Best-effort plain-text rendering of a batch digest for --dry-run.

    Mirrors _build_batch_payload as closely as ASCII allows: same header
    wording, same tight layout, same 55-char title cap, no per-line
    CVSS/KEV/EPSS repetition.
    """
    n = len(matches)
    scores = sorted([m.cve.cvss_score for m in matches if m.cve.cvss_score is not None])
    sevs_seen: list[str] = []
    sev_map = {
        "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
        "LOW": "Low", "NONE": "None", "UNKNOWN": "Unknown",
    }
    for m in matches:
        label = sev_map.get((m.cve.cvss_severity or "UNKNOWN").upper(), "Unknown")
        if label not in sevs_seen:
            sevs_seen.append(label)
    epss_vals = [m.epss for m in matches if m.epss is not None]
    kev_ids = [m.cve.cve_id for m in matches if m.kev]
    statuses = sorted({m.cve.vuln_status for m in matches})

    lines = [f"{product_name} CVEs ({n})", ""]

    if scores:
        if abs(scores[0] - scores[-1]) < 0.05:
            cvss_line = f"CVSS: {scores[0]:.1f} ("
        else:
            cvss_line = f"CVSS Range: {scores[0]:.1f} to {scores[-1]:.1f} ("
        if len(sevs_seen) == 1:
            suffix = " only" if n > 1 else ""
            cvss_line += f"{sevs_seen[0]}{suffix})"
        else:
            cvss_line += f"{', '.join(sevs_seen)})"
        lines.append(cvss_line)
    else:
        lines.append("CVSS: N/A")

    lines.append(f"Status: {', '.join(statuses)}")
    if epss_vals:
        lo, hi = min(epss_vals) * 100, max(epss_vals) * 100
        if abs(lo - hi) < 0.05:
            lines.append(f"EPSS: {lo:.1f}%")
        else:
            lines.append(f"EPSS Range: {lo:.1f}% to {hi:.1f}%")
    else:
        lines.append("EPSS: n/a")
    if kev_ids:
        lines.append(f"KEV: {len(kev_ids)} actively exploited ({', '.join(kev_ids)})")
    else:
        lines.append("KEV: None")

    lines.append("")
    lines.append("Advisories: See below")
    for i, m in enumerate(matches, 1):
        title = _derive_title(m, max_len=55)
        lines.append(f"{i}. {m.cve.cve_id}: {title}")
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


def _build_batch_payload(product_name: str, matches: list[Match]) -> dict[str, Any]:
    """Build one batch digest cardsV2 message for a product's new CVEs.

    Groups all new CVEs for a single product into a summary header (CVSS
    range, EPSS range, KEV count) and a numbered advisory list with
    hyperlinked CVE IDs.
    """
    n = len(matches)
    product_e = _esc(product_name)

    # --- summary stats ---
    scores = sorted(
        [m.cve.cvss_score for m in matches if m.cve.cvss_score is not None]
    )
    sevs_seen: list[str] = []
    for m in matches:
        s = (m.cve.cvss_severity or "UNKNOWN").upper()
        sev_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "NONE": "None", "UNKNOWN": "Unknown"}
        label = sev_map.get(s, "Unknown")
        if label not in sevs_seen:
            sevs_seen.append(label)

    epss_vals = [m.epss for m in matches if m.epss is not None]
    kev_matches = [m for m in matches if m.kev]
    statuses = sorted({m.cve.vuln_status for m in matches})

    # CVSS range line
    if scores:
        min_s = scores[0]
        max_s = scores[-1]
        if abs(min_s - max_s) < 0.05:
            cvss_html = f"<b>CVSS:</b> {min_s:.1f} ("
        else:
            cvss_html = f"<b>CVSS Range:</b> {min_s:.1f} to {max_s:.1f} ("
        # severity description. "only" suffix only makes sense when there
        # are multiple CVEs sharing one severity - otherwise it's just noise.
        if len(sevs_seen) == 1:
            s = sevs_seen[0]
            s_key = s.upper()
            color = SEVERITY_COLOR.get(s_key, SEVERITY_COLOR["UNKNOWN"])
            suffix = " only" if n > 1 else ""
            cvss_html += f"<font color=\"{_esc(color)}\"><b>{_esc(s)}</b></font>{suffix})"
        else:
            sev_parts = []
            for s in sevs_seen:
                s_key = s.upper()
                color = SEVERITY_COLOR.get(s_key, SEVERITY_COLOR["UNKNOWN"])
                sev_parts.append(
                    f"<font color=\"{_esc(color)}\"><b>{_esc(s)}</b></font>"
                )
            cvss_html += ", ".join(sev_parts) + ")"
    else:
        cvss_html = "<b>CVSS:</b> N/A"

    # Status line
    status_html = f"<b>Status:</b> {_esc(', '.join(statuses))}"

    # EPSS line: show a single value when min == max (or only one CVE has
    # an EPSS score), a range otherwise. "X% to X%" would be silly.
    if epss_vals:
        lo, hi = min(epss_vals) * 100, max(epss_vals) * 100
        if abs(lo - hi) < 0.05:
            epss_html = f"<b>EPSS:</b> {lo:.1f}%"
        else:
            epss_html = f"<b>EPSS Range:</b> {lo:.1f}% to {hi:.1f}%"
    else:
        epss_html = "<b>EPSS:</b> n/a"

    # KEV line
    if kev_matches:
        kev_list = ", ".join(
            f"<font color=\"#cc0000\"><b>{_esc(m.cve.cve_id)}</b></font>"
            for m in kev_matches
        )
        kev_html = (
            f"<b>KEV:</b> {len(kev_matches)} actively exploited ({kev_list})"
        )
    else:
        kev_html = "<b>KEV:</b> None"

    # --- advisory list ---
    # Just the CVE id + title, hyperlinked. CVSS/EPSS/KEV per line was
    # duplication - the summary header already surfaces those. Keep advisory
    # rows to the minimum: number, link, title.
    #
    # Title cap tuned for Google Chat card width. The CVE id prefix
    # ("CVE-YYYY-NNNNN: ") eats ~17 chars, so the title itself must fit in
    # the remaining ~55-60 chars to stay on one visual line. Longer NVD
    # descriptions are truncated with an ellipsis.
    advisory_lines: list[str] = []
    for i, m in enumerate(matches, 1):
        nvd_url_e = _esc(m.cve.nvd_url, quote=True)
        cve_id_e = _esc(m.cve.cve_id)
        title_e = _esc(_derive_title(m, max_len=55))
        advisory_lines.append(
            f"{i}. <a href=\"{nvd_url_e}\">{cve_id_e}: {title_e}</a>"
        )

    # --- assemble ---
    # Tight formatting: single <br> between rows, no empty lines. Google Chat
    # renders each empty string joined by <br> as an extra visible gap, which
    # is why the previous version looked spaced-out and ugly.
    header = f"<b>{product_e} CVEs</b> ({n})"
    summary_lines = "<br>".join([cvss_html, status_html, epss_html, kev_html])
    advisories_block = "<b>Advisories:</b> See below<br>" + "<br>".join(advisory_lines)

    body = f"{header}<br><br>{summary_lines}<br><br>{advisories_block}"

    # Top-level text for notification preview (plain text, simple markup).
    preview_scores = f"{scores[0]:.1f}" if scores else "N/A"
    if len(scores) > 1:
        preview_scores += f"-{scores[-1]:.1f}"
    kev_tag = ", includes KEV" if kev_matches else ""
    preview = f"{product_name} CVEs ({n}): CVSS {preview_scores}{kev_tag}"

    return {
        "text": preview,
        "cardsV2": [
            {
                "cardId": f"batch-{product_name.replace(' ', '-')}",
                "card": {
                    "sections": [
                        {"widgets": [{"textParagraph": {"text": body}}]}
                    ],
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



