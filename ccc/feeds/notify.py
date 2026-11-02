# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Google Chat card for a feed alert.

One cardsV2 per matched (or updated) feed entry:

  <Feed Name>: <entry title>   [UPDATED]
  Published: <date>
  CVEs: CVE-... (CVSS x.y Severity, KEV), ...   # when enrich: true
  Link: <entry link>
  <category footer line>

Reuses the NVD notifier's transport (_post), HTML-escaping (_esc), severity
colours, and accent-footer line so feed cards look native next to CVE cards.
All interpolated feed text is attacker-influenced free text -> escaped.
"""
from __future__ import annotations

from html import escape as _esc
from typing import Any

from ccc.feeds.enrichbridge import CveSignal
from ccc.feeds.fetch import FeedEntry
from ccc.notifier import ACCENT_LINE, SEVERITY_COLOR, NotifyError, _post, _truncate


def send_feed_alert(
    webhook_url: str,
    feed_name: str,
    entry: FeedEntry,
    signals: list[CveSignal],
    is_update: bool,
    dry_run: bool = False,
    timeout: float = 15.0,
    accent_color: str | None = None,
    category_label: str | None = None,
) -> None:
    """Send one feed-entry card. Raises NotifyError on delivery failure."""
    payload = _build_feed_payload(
        feed_name, entry, signals, is_update, accent_color, category_label
    )
    if dry_run:
        print(_dry_run_feed_render(feed_name, entry, signals, is_update, accent_color, category_label))
        return
    _post(webhook_url, payload, timeout)


def _cve_line_parts(signals: list[CveSignal]) -> list[str]:
    """Render each CVE as 'CVE-xxxx (CVSS x.y Severity, KEV)' - HTML, escaped."""
    parts: list[str] = []
    for s in signals:
        cid = _esc(s.cve_id)
        bits: list[str] = []
        if s.cvss_score is not None:
            sev_key = (s.cvss_severity or "UNKNOWN").upper()
            color = SEVERITY_COLOR.get(sev_key, SEVERITY_COLOR["UNKNOWN"])
            sev_label = (s.cvss_severity or "Unknown").capitalize()
            bits.append(
                f"{s.cvss_score:.1f} <font color=\"{_esc(color)}\"><b>{_esc(sev_label)}</b></font>"
            )
        if s.epss is not None:
            bits.append(f"EPSS {s.epss * 100:.1f}%")
        if s.kev:
            bits.append("<font color=\"#cc0000\"><b>KEV</b></font>")
        link = f"https://www.cve.org/CVERecord?id={cid}"
        label = f"{cid} ({', '.join(bits)})" if bits else cid
        parts.append(f"<a href=\"{_esc(link, quote=True)}\">{label}</a>")
    return parts


def _build_feed_payload(
    feed_name: str,
    entry: FeedEntry,
    signals: list[CveSignal],
    is_update: bool,
    accent_color: str | None,
    category_label: str | None,
) -> dict[str, Any]:
    feed_e = _esc(feed_name)
    title_e = _esc(_truncate(entry.title or "(no title)", 160))
    updated_tag = " <b>[UPDATED]</b>" if is_update else ""

    stamp = entry.published or entry.updated
    published_e = _esc(stamp.strftime("%Y-%m-%d %H:%M UTC")) if stamp else "unknown"

    lines = [f"<b>{feed_e}</b>{updated_tag}: {title_e}", f"<b>Published:</b> {published_e}"]

    if signals:
        cve_html = ", ".join(_cve_line_parts(signals))
        lines.append(f"<b>CVEs:</b> {cve_html}")

    if entry.link:
        link_e = _esc(entry.link, quote=True)
        lines.append(f"<b>Link:</b> <a href=\"{link_e}\">{link_e}</a>")

    body = "<br>".join(lines)

    if accent_color:
        accent_e = _esc(accent_color)
        footer: list[str] = []
        if category_label:
            footer.append(f"<i><font color=\"{accent_e}\">{_esc(category_label)}</font></i>")
        footer.append(f"<font color=\"{accent_e}\"><b>{ACCENT_LINE}</b></font>")
        body += "<br><br>" + "<br>".join(footer)

    card_id = f"feed-{feed_name.replace(' ', '-')}-{abs(hash(entry.item_id)) % (10**10)}"
    return {
        "cardsV2": [
            {
                "cardId": card_id,
                "card": {"sections": [{"widgets": [{"textParagraph": {"text": body}}]}]},
            }
        ],
    }


def entry_to_pending(entry: FeedEntry, signals: list[CveSignal]) -> dict[str, Any]:
    """Serialize a matched feed entry for the persisted digest store."""
    stamp = entry.published or entry.updated
    return {
        "item_id": entry.item_id,
        "title": entry.title or "(no title)",
        "link": entry.link,
        "published": stamp.isoformat() if stamp else None,
        "cves": [
            {
                "cve_id": s.cve_id,
                "cvss_score": s.cvss_score,
                "cvss_severity": s.cvss_severity,
                "kev": s.kev,
                "epss": s.epss,
            }
            for s in signals
        ],
    }


def send_feed_digest(
    webhook_url: str,
    feed_name: str,
    entries: list[dict[str, Any]],
    dry_run: bool = False,
    timeout: float = 15.0,
    accent_color: str | None = None,
    category_label: str | None = None,
) -> None:
    """Send ONE digest card for a batch-mode feed's accumulated entries."""
    if not entries:
        return
    payload = _build_feed_digest_payload(feed_name, entries, accent_color, category_label)
    if dry_run:
        print(_dry_run_feed_digest_render(feed_name, entries, accent_color, category_label))
        return
    _post(webhook_url, payload, timeout)


def _pending_cve_bits(cves: list[dict[str, Any]]) -> str:
    out: list[str] = []
    for c in cves:
        cid = _esc(c["cve_id"])
        bits: list[str] = []
        if c.get("cvss_score") is not None:
            sev_key = (c.get("cvss_severity") or "UNKNOWN").upper()
            color = SEVERITY_COLOR.get(sev_key, SEVERITY_COLOR["UNKNOWN"])
            sev_label = (c.get("cvss_severity") or "Unknown").capitalize()
            bits.append(f"{c['cvss_score']:.1f} <font color=\"{_esc(color)}\"><b>{_esc(sev_label)}</b></font>")
        if c.get("epss") is not None:
            bits.append(f"EPSS {c['epss'] * 100:.1f}%")
        if c.get("kev"):
            bits.append("<font color=\"#cc0000\"><b>KEV</b></font>")
        out.append(f"{cid} ({', '.join(bits)})" if bits else cid)
    return ", ".join(out)


def _build_feed_digest_payload(
    feed_name: str,
    entries: list[dict[str, Any]],
    accent_color: str | None,
    category_label: str | None,
) -> dict[str, Any]:
    feed_e = _esc(feed_name)
    n = len(entries)
    lines = [f"<b>{feed_e}</b> ({n} update{'s' if n != 1 else ''})"]
    for i, e in enumerate(entries, 1):
        title_e = _esc(_truncate(e.get("title") or "(no title)", 120))
        link = e.get("link") or ""
        if link:
            link_e = _esc(link, quote=True)
            row = f"{i}. <a href=\"{link_e}\">{title_e}</a>"
        else:
            row = f"{i}. {title_e}"
        cves = e.get("cves") or []
        if cves:
            row += f"<br>&nbsp;&nbsp;&nbsp;{_pending_cve_bits(cves)}"
        lines.append(row)

    body = "<br>".join(lines)
    if accent_color:
        accent_e = _esc(accent_color)
        footer: list[str] = []
        if category_label:
            footer.append(f"<i><font color=\"{accent_e}\">{_esc(category_label)}</font></i>")
        footer.append(f"<font color=\"{accent_e}\"><b>{ACCENT_LINE}</b></font>")
        body += "<br><br>" + "<br>".join(footer)

    return {
        "cardsV2": [
            {
                "cardId": f"feed-digest-{feed_name.replace(' ', '-')}",
                "card": {"sections": [{"widgets": [{"textParagraph": {"text": body}}]}]},
            }
        ],
    }


def _dry_run_feed_digest_render(
    feed_name: str,
    entries: list[dict[str, Any]],
    accent_color: str | None,
    category_label: str | None,
) -> str:
    n = len(entries)
    lines = [f"{feed_name} ({n} update{'s' if n != 1 else ''})"]
    for i, e in enumerate(entries, 1):
        lines.append(f"{i}. {e.get('title') or '(no title)'}")
        cves = e.get("cves") or []
        if cves:
            bits = []
            for c in cves:
                extra = []
                if c.get("cvss_score") is not None:
                    extra.append(f"{c['cvss_score']:.1f} {(c.get('cvss_severity') or 'Unknown').capitalize()}")
                if c.get("epss") is not None:
                    extra.append(f"EPSS {c['epss'] * 100:.1f}%")
                if c.get("kev"):
                    extra.append("KEV")
                bits.append(f"{c['cve_id']} ({', '.join(extra)})" if extra else c["cve_id"])
            lines.append("   " + ", ".join(bits))
        if e.get("link"):
            lines.append(f"   {e['link']}")
    if accent_color and category_label:
        lines.append(f"Footer: <{category_label}> line in {accent_color}")
    elif accent_color:
        lines.append(f"Footer: line in {accent_color}")
    return "\n".join(lines)


def _dry_run_feed_render(
    feed_name: str,
    entry: FeedEntry,
    signals: list[CveSignal],
    is_update: bool,
    accent_color: str | None,
    category_label: str | None,
) -> str:
    upd = " [UPDATED]" if is_update else ""
    stamp = entry.published or entry.updated
    published = stamp.strftime("%Y-%m-%d %H:%M UTC") if stamp else "unknown"
    lines = [
        f"{feed_name}{upd}: {entry.title or '(no title)'}",
        f"Published: {published}",
    ]
    if signals:
        cve_bits = []
        for s in signals:
            extra = []
            if s.cvss_score is not None:
                extra.append(f"{s.cvss_score:.1f} {(s.cvss_severity or 'Unknown').capitalize()}")
            if s.epss is not None:
                extra.append(f"EPSS {s.epss * 100:.1f}%")
            if s.kev:
                extra.append("KEV")
            cve_bits.append(f"{s.cve_id} ({', '.join(extra)})" if extra else s.cve_id)
        lines.append("CVEs: " + ", ".join(cve_bits))
    if entry.link:
        lines.append(f"Link: {entry.link}")
    if accent_color and category_label:
        lines.append(f"Footer: <{category_label}> line in {accent_color}")
    elif accent_color:
        lines.append(f"Footer: line in {accent_color}")
    return "\n".join(lines)
