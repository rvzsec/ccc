# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Fetch + parse Atom/RSS feeds into normalized FeedEntry records.

Parsing goes through defusedxml so malicious feeds cannot mount XXE /
billion-laughs / external-entity attacks. The parse step is pure (string ->
entries) so it is trivially testable without network.

We normalize both formats onto the same FeedEntry so downstream filter/notify
code never has to know whether the source was Atom or RSS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from defusedxml import ElementTree as DET

from ccc._logging import log

ATOM_NS = "{http://www.w3.org/2005/Atom}"


class FeedError(Exception):
    """Feed fetch or parse failed. Non-fatal: the run continues with other feeds."""


@dataclass
class FeedEntry:
    """One normalized feed entry (Atom <entry> or RSS <item>)."""

    item_id: str                 # stable identity: atom <id> / rss <guid> | link
    title: str
    link: str
    published: datetime | None
    updated: datetime | None
    summary: str
    content: str
    fields: dict[str, str] = field(default_factory=dict)       # author, category, ...
    extracted: dict[str, list[str]] = field(default_factory=dict)

    def field_value(self, name: str) -> str:
        """Return a filterable/extractable field as a string (never None)."""
        builtin = {
            "title": self.title,
            "link": self.link,
            "id": self.item_id,
            "summary": self.summary,
            "content": self.content,
            "published": self.published.isoformat() if self.published else "",
            "updated": self.updated.isoformat() if self.updated else "",
        }
        if name in builtin:
            return builtin[name]
        return self.fields.get(name, "")


# ---------- transport ----------

def fetch_feed(
    url: str,
    fmt: str,
    timeout: float = 30.0,
    user_agent: str = "ccc/0.1 (+https://github.com/rvzsec/ccc)",
) -> list[FeedEntry]:
    """GET the feed and parse it. Raises FeedError on any failure."""
    headers = {"User-Agent": user_agent, "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml"}
    try:
        with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True) as client:
            resp = client.get(url)
    except httpx.HTTPError as e:
        raise FeedError(f"feed request failed: {e}") from e
    if resp.status_code >= 400:
        raise FeedError(f"feed HTTP {resp.status_code}: {resp.text[:200]}")
    return parse_feed(resp.text, fmt)


# ---------- parsing (pure) ----------

def parse_feed(raw: str, fmt: str) -> list[FeedEntry]:
    """Parse feed XML text into FeedEntry list. Pure - no network."""
    try:
        root = DET.fromstring(raw.encode("utf-8") if isinstance(raw, str) else raw)
    except Exception as e:  # defusedxml raises on entity bombs etc.
        raise FeedError(f"feed XML parse failed: {e}") from e

    if fmt == "atom":
        return _parse_atom(root)
    if fmt == "rss":
        return _parse_rss(root)
    raise FeedError(f"unsupported feed format {fmt!r}")


def _parse_atom(root: Any) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for e in root.findall(f"{ATOM_NS}entry"):
        item_id = _text(e.find(f"{ATOM_NS}id"))
        title = _text(e.find(f"{ATOM_NS}title"))
        link = _atom_link(e)
        published = _parse_iso(_text(e.find(f"{ATOM_NS}published")))
        updated = _parse_iso(_text(e.find(f"{ATOM_NS}updated")))
        summary = _text(e.find(f"{ATOM_NS}summary"))
        content = _text(e.find(f"{ATOM_NS}content"))
        author = _text(e.find(f"{ATOM_NS}author/{ATOM_NS}name"))
        categories = ", ".join(
            c.get("term", "") for c in e.findall(f"{ATOM_NS}category") if c.get("term")
        )
        # Identity fallbacks: id -> link -> title. Something stable must exist.
        stable = item_id or link or title
        if not stable:
            continue
        entries.append(
            FeedEntry(
                item_id=stable,
                title=title,
                link=link or item_id,
                published=published,
                updated=updated,
                summary=summary,
                content=content,
                fields={"author": author, "category": categories},
            )
        )
    return entries


def _parse_rss(root: Any) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    # RSS core elements are unnamespaced; items live under channel/item.
    for item in root.iter("item"):
        title = _text(item.find("title"))
        link = _text(item.find("link"))
        guid = _text(item.find("guid"))
        pub = _parse_rfc822(_text(item.find("pubDate")))
        desc = _text(item.find("description"))
        # content:encoded (RSS content module) if present, else description.
        content = desc
        for child in item:
            if child.tag.endswith("}encoded") or child.tag.endswith("encoded"):
                content = (child.text or "").strip() or content
        author = _text(item.find("author")) or _text(item.find("dc:creator"))
        categories = ", ".join(
            (c.text or "").strip() for c in item.findall("category") if (c.text or "").strip()
        )
        stable = guid or link or title
        if not stable:
            continue
        entries.append(
            FeedEntry(
                item_id=stable,
                title=title,
                link=link or guid,
                published=pub,
                updated=pub,
                summary=desc,
                content=content,
                fields={"author": author, "category": categories},
            )
        )
    return entries


# ---------- helpers ----------

def _text(node: Any) -> str:
    if node is None:
        return ""
    # Atom content/summary may carry nested HTML as text or children.
    if node.text:
        return node.text.strip()
    # Reconstruct text from children if the element had mixed/child content.
    try:
        inner = "".join(node.itertext())
        return inner.strip()
    except Exception:
        return ""


def _atom_link(entry: Any) -> str:
    """Prefer rel=alternate; fall back to the first link with an href."""
    first = ""
    for ln in entry.findall(f"{ATOM_NS}link"):
        href = ln.get("href", "")
        if not href:
            continue
        if ln.get("rel", "alternate") == "alternate":
            return href
        if not first:
            first = href
    return first


def _parse_iso(raw: str) -> datetime | None:
    if not raw:
        return None
    s = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        log.debug("unparseable ISO date in feed: %r", raw)
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_rfc822(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
