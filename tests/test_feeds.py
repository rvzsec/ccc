"""Feed-source tests: parse, filter, extract, dedup, retention, card safety.

Mirrors tests/test_dedup.py in spirit - exercises the generic feed machinery
without touching the network.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ccc.feeds.config import load_feeds
from ccc.feeds.fetch import FeedError, parse_feed
from ccc.feeds.filter import entry_matches, run_extracts
from ccc.config import Category
from ccc.state import (
    FEED_SEEN_GRACE,
    check_and_mark_feed,
    hash_feed_entry,
    load_feed_seen,
    save_feed_seen,
)

ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>GitLab Releases</title>
  <entry>
    <title>GitLab Security Release: 19.5.1</title>
    <link href="https://docs.gitlab.com/releases/sec-19-5-1/" rel="alternate"/>
    <id>https://docs.gitlab.com/releases/sec-19-5-1/</id>
    <published>2026-10-21T00:00:00Z</published>
    <updated>2026-10-21T00:00:00Z</updated>
    <author><name>GitLab</name></author>
    <content type="html"><![CDATA[<p>Fixes CVE-2026-110264 and CVE-2026-15723.</p>]]></content>
  </entry>
  <entry>
    <title>GitLab Patch Release: 19.5.0</title>
    <link href="https://docs.gitlab.com/releases/patch-19-5-0/" rel="alternate"/>
    <id>https://docs.gitlab.com/releases/patch-19-5-0/</id>
    <published>2026-10-15T00:00:00Z</published>
    <updated>2026-10-15T00:00:00Z</updated>
    <content type="html"><![CDATA[<p>Routine bug fixes, no security content.</p>]]></content>
  </entry>
</feed>
"""

RSS = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Acme Advisories</title>
    <item>
      <title>Acme Advisory CVE-2026-9999</title>
      <link>https://acme.example/adv/1</link>
      <guid>acme-adv-1</guid>
      <pubDate>Wed, 21 Oct 2026 00:00:00 +0000</pubDate>
      <description>Critical RCE, CVE-2026-9999.</description>
    </item>
  </channel>
</rss>
"""

# Classic billion-laughs entity expansion bomb.
BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>&lol3;</title>
<id>x</id></entry></feed>
"""


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


class ParseTest(unittest.TestCase):
    def test_atom_parse(self) -> None:
        entries = parse_feed(ATOM, "atom")
        self.assertEqual(len(entries), 2)
        e = entries[0]
        self.assertEqual(e.item_id, "https://docs.gitlab.com/releases/sec-19-5-1/")
        self.assertEqual(e.title, "GitLab Security Release: 19.5.1")
        self.assertEqual(e.link, "https://docs.gitlab.com/releases/sec-19-5-1/")
        self.assertIn("CVE-2026-110264", e.content)
        self.assertEqual(e.published, utc("2026-10-21T00:00:00"))
        self.assertEqual(e.fields.get("author"), "GitLab")

    def test_rss_parse(self) -> None:
        entries = parse_feed(RSS, "rss")
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.item_id, "acme-adv-1")
        self.assertEqual(e.link, "https://acme.example/adv/1")
        self.assertIn("CVE-2026-9999", e.content)
        self.assertEqual(e.published, utc("2026-10-21T00:00:00"))

    def test_billion_laughs_rejected(self) -> None:
        # defusedxml must refuse the entity bomb rather than expand it.
        with self.assertRaises(FeedError):
            parse_feed(BOMB, "atom")


class FilterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = parse_feed(ATOM, "atom")

    def _feed(self, match_yaml: str):
        cats = {"default": Category(name="default")}
        import tempfile as _t

        p = Path(_t.mktemp(suffix=".yaml"))
        p.write_text(
            "feeds:\n"
            "  - name: t\n"
            "    url: https://x.example/f.xml\n"
            "    format: atom\n" + match_yaml
        )
        return load_feeds(p, cats)[0]

    def test_contains_case_insensitive(self) -> None:
        feed = self._feed(
            "    match:\n      any:\n"
            "        - { field: title, contains: ['security'] }\n"
        )
        matched = [e for e in self.entries if entry_matches(e, feed.match)]
        self.assertEqual(len(matched), 1)
        self.assertIn("Security", matched[0].title)

    def test_regex_on_content(self) -> None:
        feed = self._feed(
            "    match:\n      any:\n"
            "        - { field: content, regex: 'CVE-\\d{4}-\\d+' }\n"
        )
        matched = [e for e in self.entries if entry_matches(e, feed.match)]
        # Both entries mention no CVE in #2, so only the security one matches.
        self.assertEqual(len(matched), 1)

    def test_no_match_block_alerts_all(self) -> None:
        feed = self._feed("")
        matched = [e for e in self.entries if entry_matches(e, feed.match)]
        self.assertEqual(len(matched), 2)

    def test_all_and_any_combine(self) -> None:
        feed = self._feed(
            "    match:\n"
            "      all:\n"
            "        - { field: title, contains: ['GitLab'] }\n"
            "      any:\n"
            "        - { field: content, regex: 'CVE-\\d{4}-\\d+' }\n"
        )
        matched = [e for e in self.entries if entry_matches(e, feed.match)]
        self.assertEqual(len(matched), 1)

    def test_extract_cves_dedup_ordered(self) -> None:
        feed = self._feed(
            "    extract:\n      cves: { from: content, regex: 'CVE-\\d{4}-\\d+' }\n"
        )
        got = run_extracts(self.entries[0], feed.extract)
        self.assertEqual(got["cves"], ["CVE-2026-110264", "CVE-2026-15723"])


class DedupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ccc-feed-"))

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sig(self, entry) -> str:
        stamp = (entry.updated or entry.published).isoformat()
        return hash_feed_entry(entry.title, stamp, entry.content)

    def test_same_feed_twice_no_realerts(self) -> None:
        entries = parse_feed(ATOM, "atom")
        now = utc("2026-10-21T01:00:00")

        seen = load_feed_seen(self.tmp)
        first = [
            check_and_mark_feed(seen, "GitLab", e.item_id, self._sig(e), now)
            for e in entries
        ]
        save_feed_seen(self.tmp, seen, now)
        self.assertEqual([a for a, _ in first], [True, True])

        # Second poll, same feed, 1h later.
        later = now + timedelta(hours=1)
        seen = load_feed_seen(self.tmp)
        second = [
            check_and_mark_feed(seen, "GitLab", e.item_id, self._sig(e), later)
            for e in entries
        ]
        self.assertEqual([a for a, _ in second], [False, False])

    def test_new_entry_fires_once(self) -> None:
        entries = parse_feed(ATOM, "atom")
        now = utc("2026-10-21T01:00:00")
        seen = load_feed_seen(self.tmp)
        for e in entries:
            check_and_mark_feed(seen, "GitLab", e.item_id, self._sig(e), now)
        save_feed_seen(self.tmp, seen, now)

        # A new entry appears in the next poll.
        new_entry = parse_feed(ATOM, "atom")[0]
        new_entry.item_id = "https://docs.gitlab.com/releases/sec-19-5-2/"
        later = now + timedelta(hours=1)
        seen = load_feed_seen(self.tmp)
        should, is_upd = check_and_mark_feed(
            seen, "GitLab", new_entry.item_id, self._sig(new_entry), later
        )
        self.assertTrue(should)
        self.assertFalse(is_upd)

    def test_changed_entry_is_update(self) -> None:
        e = parse_feed(ATOM, "atom")[0]
        now = utc("2026-10-21T01:00:00")
        seen = load_feed_seen(self.tmp)
        check_and_mark_feed(seen, "GitLab", e.item_id, self._sig(e), now)

        # Body edited + updated timestamp bumped -> new signature.
        e.content += " Additional note added."
        e.updated = utc("2026-10-22T00:00:00")
        later = now + timedelta(days=1)
        should, is_upd = check_and_mark_feed(
            seen, "GitLab", e.item_id, self._sig(e), later
        )
        self.assertTrue(should)
        self.assertTrue(is_upd)

    def test_retention_prunes_scrolled_off(self) -> None:
        now = utc("2026-01-01T00:00:00")
        seen = load_feed_seen(self.tmp)
        check_and_mark_feed(seen, "GitLab", "old-id", "h", now)
        save_feed_seen(self.tmp, seen, now)

        # Far future poll where the old entry is no longer in the feed: it is
        # not re-marked, so it ages past the grace TTL and is pruned.
        future = now + FEED_SEEN_GRACE + timedelta(days=1)
        seen = load_feed_seen(self.tmp)
        save_feed_seen(self.tmp, seen, future)
        reloaded = load_feed_seen(self.tmp)
        self.assertNotIn("old-id", reloaded.get("GitLab", {}))


class BatchDigestTest(unittest.TestCase):
    def test_entry_to_pending_and_digest_card(self) -> None:
        from ccc.feeds.enrichbridge import CveSignal
        from ccc.feeds.fetch import FeedEntry
        from ccc.feeds.notify import _build_feed_digest_payload, entry_to_pending

        e = FeedEntry(
            item_id="id-1",
            title="Security Release 1.2.3",
            link="https://vendor.example/r/1",
            published=utc("2026-10-21T00:00:00"),
            updated=None,
            summary="",
            content="",
        )
        sigs = [CveSignal(cve_id="CVE-2026-1", cvss_score=9.8, cvss_severity="CRITICAL", kev=True, epss=0.9)]
        pend = entry_to_pending(e, sigs)
        self.assertEqual(pend["item_id"], "id-1")
        self.assertEqual(pend["cves"][0]["cve_id"], "CVE-2026-1")

        payload = _build_feed_digest_payload("Vendor", [pend], "#cc0000", "Tier 1")
        body = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["textParagraph"]["text"]
        self.assertIn("Vendor", body)
        self.assertIn("CVE-2026-1", body)
        self.assertIn("KEV", body)
        self.assertIn("Tier 1", body)


class CardSafetyTest(unittest.TestCase):
    def test_html_escaped_in_card(self) -> None:
        from ccc.feeds.fetch import FeedEntry
        from ccc.feeds.notify import _build_feed_payload

        entry = FeedEntry(
            item_id="x",
            title="<script>alert(1)</script>",
            link="https://evil.example/\"><b>",
            published=utc("2026-10-21T00:00:00"),
            updated=None,
            summary="",
            content="",
        )
        payload = _build_feed_payload("Feed<>", entry, [], False, None, None)
        body = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["textParagraph"]["text"]
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)


if __name__ == "__main__":
    unittest.main()
