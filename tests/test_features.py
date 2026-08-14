"""Tests for min_cve_year filter + tiered categories with periodic digests.

Covered:
  - find_matches honors min_cve_year (config.yaml)
  - products.yaml category parsing: default, explicit, override, errors
  - pending-batch accumulation across runs, period flush, dedup, failure retry
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from ccc.config import Config, build_product
from ccc.nvd import CpeMatch, NvdCve


def utc(s: str) -> datetime:
    """Helper: parse a fixed-format UTC timestamp."""
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


class _FakeDatetime(datetime):
    """datetime subclass whose now() returns a fixed value.

    run_once calls datetime.now(timezone.utc) internally; tests patch
    ccc.runner.datetime with this so the digest period math is deterministic.
    fromisoformat/timedelta comparisons inherit the real implementations.
    """

    _now: datetime | None = None

    @classmethod
    def now(cls, tz=None):
        assert cls._now is not None, "set _FakeDatetime._now before running"
        if tz is not None:
            return cls._now.astimezone(tz)
        return cls._now


def _cfg(tmpdir: Path, **overrides) -> Config:
    return Config(
        google_chat_webhook="https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t",
        state_dir=Path(tmpdir),
        severity_floor="low",
        max_lookback_hours=24,
        **overrides,
    )


def _cve(cve_id: str, product: str, published: datetime) -> NvdCve:
    return NvdCve(
        cve_id=cve_id,
        published=published,
        last_modified=published + timedelta(hours=1),
        vuln_status="Analyzed",
        description="a vulnerability in " + product,
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N",
        cpes=[CpeMatch(cpe=f"cpe:2.3:a:acme:{product}:*", vulnerable=True)],
    )


# ============================================================
# Feature 1: min_cve_year
# ============================================================

class YearFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-year-"))
        self.product = build_product("Acme Widget", "cpe:2.3:a:acme:widget:*")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, cves: list[NvdCve], min_year: int | None) -> list[str]:
        from ccc.matcher import find_matches
        cfg = _cfg(self.tmpdir, min_cve_year=min_year)
        matches = find_matches(cves, [self.product], cfg, {}, {})
        return [m.cve.cve_id for m in matches]

    def test_old_cve_filtered_when_cutoff_set(self) -> None:
        old = _cve("CVE-2022-0001", "widget", utc("2022-06-01T00:00:00"))
        new = _cve("CVE-2026-0001", "widget", utc("2026-06-01T00:00:00"))
        self.assertEqual(self._run([old, new], 2025), ["CVE-2026-0001"])

    def test_cutoff_boundary_inclusive(self) -> None:
        edge = _cve("CVE-2025-0001", "widget", utc("2025-01-01T00:00:00"))
        self.assertEqual(self._run([edge], 2025), ["CVE-2025-0001"])

    def test_default_no_limit_keeps_old_behavior(self) -> None:
        old = _cve("CVE-2022-0001", "widget", utc("2022-06-01T00:00:00"))
        self.assertEqual(self._run([old], None), ["CVE-2022-0001"])

    def test_year_gate_runs_before_match(self) -> None:
        """Old CVE never even reaches the matcher - no false positives."""
        from ccc.matcher import find_matches
        cfg = _cfg(self.tmpdir, min_cve_year=2025)
        old = _cve("CVE-2022-0001", "widget", utc("2022-06-01T00:00:00"))
        matches = find_matches([old], [self.product], cfg, {}, {})
        self.assertEqual(matches, [])


# ============================================================
# Feature 2: categories in products.yaml
# ============================================================

class CategoryConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-cat-"))
        self.yaml = self.tmpdir / "products.yaml"

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _load(self) -> tuple[dict[str, Any], list[Any]]:
        from ccc.config import load_categories_and_products
        return load_categories_and_products(self.yaml)

    def test_implicit_default_category(self) -> None:
        self.yaml.write_text(
            "products:\n  - name: 'App'\n    cpe: 'cpe:2.3:a:acme:app:*'\n",
            encoding="utf-8",
        )
        cats, entries = self._load()
        self.assertIn("default", cats)
        self.assertEqual(cats["default"].alert_mode, "individual")
        self.assertEqual(len(entries), 1)

    def test_explicit_categories_resolved(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  consumer:\n"
            "    alert_mode: batch\n"
            "    batch_period: weekly\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n"
            "    category: consumer\n",
            encoding="utf-8",
        )
        cats, entries = self._load()
        self.assertEqual(cats["consumer"].alert_mode, "batch")
        self.assertEqual(cats["consumer"].batch_period, "weekly")
        self.assertEqual(entries[0]["category"], "consumer")

    def test_unknown_category_raises(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  server:\n"
            "    alert_mode: individual\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n"
            "    category: nope\n",
            encoding="utf-8",
        )
        from ccc.config import load_categories_and_products
        with self.assertRaises(ValueError) as ctx:
            load_categories_and_products(self.yaml)
        self.assertIn("unknown category", str(ctx.exception))

    def test_bad_category_policy_raises(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  consumer:\n"
            "    alert_mode: telepathically\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n",
            encoding="utf-8",
        )
        from ccc.config import load_categories_and_products
        with self.assertRaises(ValueError):
            load_categories_and_products(self.yaml)

    def test_plain_string_entries_use_default(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  consumer:\n"
            "    alert_mode: batch\n"
            "    batch_period: weekly\n"
            "products:\n"
            "  - someapp\n",
            encoding="utf-8",
        )
        cats, entries = self._load()
        self.assertIsInstance(entries[0], str)  # plain names flow through as-is

    def test_accent_color_parsed_from_category(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  consumer:\n"
            "    alert_mode: batch\n"
            "    batch_period: weekly\n"
            "    accent_color: \"#cc0000\"\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n"
            "    category: consumer\n",
            encoding="utf-8",
        )
        cats, _ = self._load()
        self.assertEqual(cats["consumer"].accent_color, "#cc0000")
        self.assertIsNone(cats["default"].accent_color)

    def test_category_label_parsed(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  tier1:\n"
            "    alert_mode: individual\n"
            "    label: \"Tier 1 - Production Stack\"\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n"
            "    category: tier1\n",
            encoding="utf-8",
        )
        cats, _ = self._load()
        self.assertEqual(cats["tier1"].label, "Tier 1 - Production Stack")

    def test_invalid_accent_color_raises(self) -> None:
        self.yaml.write_text(
            "categories:\n"
            "  consumer:\n"
            "    alert_mode: individual\n"
            "    accent_color: \"red\"\n"
            "products:\n"
            "  - name: 'App'\n"
            "    cpe: 'cpe:2.3:a:acme:app:*'\n",
            encoding="utf-8",
        )
        from ccc.config import load_categories_and_products
        with self.assertRaises(ValueError):
            load_categories_and_products(self.yaml)


class AccentNotifierTest(unittest.TestCase):
    """Category accent footer renders into both card types."""

    def _match(self, accent: str | None = None, category: str | None = None,
               category_label: str | None = None):
        from ccc.config import Product
        from ccc.matcher import Match
        from ccc.nvd import CpeMatch, NvdCve
        prod = Product(
            name="Acme Widget", cpe="cpe:2.3:a:acme:widget:*",
            accent_color=accent,
            category=category or "default",
            category_label=category_label,
        )
        cve = NvdCve(
            cve_id="CVE-2026-9901",
            published=utc("2026-01-01T00:00:00"),
            last_modified=utc("2026-01-01T00:00:00"),
            vuln_status="Analyzed",
            description="test",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N",
            cpes=[CpeMatch(cpe="cpe:2.3:a:acme:widget:*", vulnerable=True)],
        )
        return Match(cve=cve, products=[prod], epss=0.5, kev=False, kev_name="")

    def _body(self, payload) -> str:
        return payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["textParagraph"]["text"]

    def test_individual_card_has_accent_footer(self) -> None:
        from ccc.notifier import _build_payload
        body = self._body(_build_payload(self._match(accent="#cc0000"), is_update=False))
        self.assertIn('font color="#cc0000"', body)
        self.assertIn("\u2501", body)  # the box-drawing line chars

    def test_individual_card_tier_label_italic_in_accent_color(self) -> None:
        from ccc.notifier import _build_payload
        body = self._body(_build_payload(
            self._match(accent="#cc0000", category="tier1"), is_update=False))
        self.assertIn(
            '<i><font color="#cc0000">tier1</font></i>', body,
            "tier label must be italic and use the accent color",
        )

    def test_individual_card_tier_label_uses_display_label(self) -> None:
        from ccc.notifier import _build_payload
        body = self._body(_build_payload(
            self._match(accent="#cc0000", category="tier1",
                        category_label="Tier 1 - Production Stack"),
            is_update=False))
        self.assertIn(
            '<i><font color="#cc0000">Tier 1 - Production Stack</font></i>',
            body, "footer shows the pretty label, not the raw category key",
        )
        self.assertNotIn("tier1</font></i>", body)

    def test_individual_card_default_category_no_label(self) -> None:
        from ccc.notifier import _build_payload
        body = self._body(_build_payload(self._match(accent="#cc0000"), is_update=False))
        self.assertNotIn("<i>", body, "untiered products get the line but no label")

    def test_individual_card_no_accent_no_footer(self) -> None:
        from ccc.notifier import _build_payload
        body = self._body(_build_payload(self._match(), is_update=False))
        self.assertNotIn("\u2501", body)

    def test_digest_card_has_accent_footer(self) -> None:
        from ccc.notifier import _build_digest_payload
        entry = {
            "cve_id": "CVE-2026-9902",
            "title": "x",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "epss": None,
            "kev": False,
            "vuln_status": "Analyzed",
        }
        body = self._body(_build_digest_payload("Acme", [entry], accent_color="#d4ac0d"))
        self.assertIn('font color="#d4ac0d"', body)
        self.assertIn("\u2501", body)

    def test_digest_card_tier_label_italic_in_accent_color(self) -> None:
        from ccc.notifier import _build_digest_payload
        entry = {
            "cve_id": "CVE-2026-9902",
            "title": "x",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "epss": None,
            "kev": False,
            "vuln_status": "Analyzed",
        }
        body = self._body(_build_digest_payload(
            "Acme", [entry], accent_color="#d4ac0d", category="tier3"))
        self.assertIn(
            '<i><font color="#d4ac0d">tier3</font></i>', body,
            "digest tier label must be italic and use the accent color",
        )

    def test_digest_card_no_accent_no_footer(self) -> None:
        from ccc.notifier import _build_digest_payload
        entry = {
            "cve_id": "CVE-2026-9902",
            "title": "x",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "epss": None,
            "kev": False,
            "vuln_status": "Analyzed",
        }
        body = self._body(_build_digest_payload("Acme", [entry]))
        self.assertNotIn("\u2501", body)

    def test_digest_card_groups_entries_by_product(self) -> None:
        """One tier card, entries grouped under product sub-headers."""
        from ccc.notifier import _build_digest_payload
        entries = [
            {
                "cve_id": "CVE-2026-99101", "title": "x1",
                "cvss_score": 9.8, "severity": "CRITICAL",
                "epss": None, "kev": False, "vuln_status": "Analyzed",
                "products": ["Product A"],
            },
            {
                "cve_id": "CVE-2026-99102", "title": "x2",
                "cvss_score": 8.1, "severity": "HIGH",
                "epss": None, "kev": False, "vuln_status": "Analyzed",
                "products": ["Product A"],
            },
            {
                "cve_id": "CVE-2026-99103", "title": "x3",
                "cvss_score": 7.5, "severity": "HIGH",
                "epss": None, "kev": False, "vuln_status": "Analyzed",
                "products": ["Product B"],
            },
        ]
        body = self._body(_build_digest_payload("tier3", entries))
        self.assertIn("<b>C³ - New CVE Alerts</b>", body, "generic top line")
        self.assertIn("<b>Product A</b> (2)", body, "product sub-header A with count")
        self.assertIn("<b>Product B</b> (1)", body, "product sub-header B with count")
        # Continuous numbering across groups: CVE 3 is line 3, under Product B.
        a_idx = body.find("Product A")
        b_idx = body.find("Product B")
        self.assertIn("CVE-2026-99103: x3", body[a_idx:])
        self.assertLess(a_idx, b_idx, "Product A group renders before Product B")
        self.assertIn("3. <a", body)
        # No blank line between CVEs under the same product; blank line only
        # between product groups.
        self.assertIn("1. <a", body)
        self.assertIn("<br>2. <a", body, "single break between CVEs in a group")
        self.assertIn("2. <a", body)
        self.assertIn("<br><br><b>Product B</b>", body,
                      "blank line only between product groups")


# ============================================================
# Feature 2: pending digest accumulation + flush (runner level)
# ============================================================

class PendingBatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-batch-"))
        self.weekly = build_product(
            "Weekly App", "cpe:2.3:a:acme:weekly_app:*",
            alert_mode="batch", batch_period="weekly", category="tier3",
        )
        self.daily = build_product(
            "Daily App", "cpe:2.3:a:acme:daily_app:*",
            alert_mode="batch", batch_period="daily", category="tier2",
        )
        self.individual = build_product(
            "Prod App", "cpe:2.3:a:acme:prod_app:*",
            alert_mode="individual", category="tier1",
        )
        # Fresh KEV cache so fetch_kev works offline.
        (self.tmpdir / "kev.json").write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "names": {},
        }), encoding="utf-8")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(
        self,
        now: datetime,
        cves: list[NvdCve],
        cfg_override: Config | None = None,
    ) -> MagicMock:
        """Drive run_once with faked NVD + frozen clock. Returns the digest mock."""
        from ccc.runner import run_once

        class FakeNvdClient:
            def __init__(self, api_key=None, **kwargs):
                self._cves = cves

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetch_window(self, start, end):
                return self._cves

        digest_mock = MagicMock()
        alert_mock = MagicMock()

        _FakeDatetime._now = now
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", digest_mock),
            patch("ccc.runner.send_alert", alert_mock),
        ):
            cfg = cfg_override or _cfg(self.tmpdir)
            run_once(cfg, [self.weekly, self.daily, self.individual], dry_run=False)
        return digest_mock

    def _pending(self) -> dict[str, Any]:
        from ccc.state import load_pending
        return load_pending(self.tmpdir)

    def test_accumulates_until_period_due(self) -> None:
        """Weekly tier: entries accumulate across runs, no send until due."""
        t0 = utc("2026-07-01T00:00:00")
        cve1 = _cve("CVE-2026-1001", "weekly_app", t0)
        cve2 = _cve("CVE-2026-1002", "weekly_app", t0)

        # Run 1: two CVEs enqueued into the tier3 bucket, nothing sent.
        digest1 = self._run(t0, [cve1, cve2])
        digest1.assert_not_called()
        pending = self._pending()
        self.assertEqual(len(pending["tier3"]["entries"]), 2)

        # Run 2 (next hour, NVD re-emits same CVEs): refreshed, still 2, no send.
        digest2 = self._run(t0 + timedelta(hours=1), [cve1, cve2])
        digest2.assert_not_called()
        self.assertEqual(len(self._pending()["tier3"]["entries"]), 2)

        # Run 3: past the weekly due date -> ONE digest, both CVEs.
        digest3 = self._run(t0 + timedelta(days=8), [cve1, cve2])
        self.assertEqual(digest3.call_count, 1)
        args = digest3.call_args
        self.assertEqual(args[0][1], "tier3")
        self.assertEqual([e["cve_id"] for e in args[0][2]], ["CVE-2026-1001", "CVE-2026-1002"])
        self.assertEqual(args[0][2][0]["products"], ["Weekly App"])
        # Bucket cleared + CVEs now in recent.json.
        self.assertEqual(self._pending().get("tier3", {}).get("entries"), None)
        from ccc.state import load_recent
        recent = load_recent(self.tmpdir)
        self.assertIn("CVE-2026-1001", recent)
        self.assertIn("CVE-2026-1002", recent)

    def test_flushed_cves_not_requeued(self) -> None:
        """After a flush, the same CVE re-appearing is suppressed."""
        t0 = utc("2026-07-01T00:00:00")
        cve = _cve("CVE-2026-2001", "weekly_app", t0)

        self._run(t0, [cve])                          # enqueue
        flush_digest = self._run(t0 + timedelta(days=8), [cve])  # flush
        self.assertEqual(flush_digest.call_count, 1)
        later_digest = self._run(t0 + timedelta(days=9), [cve])  # re-emission
        later_digest.assert_not_called()  # already in recent.json -> not re-queued

    def test_flush_failure_keeps_entries_and_raises(self) -> None:
        """NotifyError on flush -> DeliveryFailure, entries persist for retry."""
        from ccc.notifier import NotifyError
        from ccc.runner import DeliveryFailure, run_once
        t0 = utc("2026-07-01T00:00:00")
        cve = _cve("CVE-2026-3001", "weekly_app", t0)

        class FakeNvdClient:
            def __init__(self, api_key=None, **kwargs):
                self._cves = [cve]

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetch_window(self, start, end):
                return self._cves

        cfg = _cfg(self.tmpdir)

        # Run 1 (t0): enqueue. Bucket is created, next_due = t0 + 7d.
        _FakeDatetime._now = t0
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert"),
            patch("ccc.runner.send_alert"),
        ):
            run_once(cfg, [self.weekly], dry_run=False)

        # Run 2 (t0+8d): flush is due and the webhook fails.
        _FakeDatetime._now = t0 + timedelta(days=8)
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", side_effect=NotifyError("boom")),
            patch("ccc.runner.send_alert"),
        ):
            with self.assertRaises(DeliveryFailure):
                run_once(cfg, [self.weekly], dry_run=False)

        # Entries survived; next run will retry the flush.
        pending = self._pending()
        self.assertEqual(len(pending["tier3"]["entries"]), 1)
        # last_run must NOT have advanced past run 1 (the failed run leaves it put).
        from ccc.state import read_last_run
        self.assertEqual(read_last_run(self.tmpdir), t0)

    def test_empty_window_still_flushes_due_batch(self) -> None:
        """A run with zero new CVEs still flushes an overdue digest."""
        t0 = utc("2026-07-01T00:00:00")
        cve = _cve("CVE-2026-4001", "daily_app", t0)

        self._run(t0, [cve])                               # enqueue (daily)
        digest = self._run(t0 + timedelta(days=2), [])     # empty NVD window
        self.assertEqual(digest.call_count, 1)
        args = digest.call_args
        self.assertEqual(args[0][1], "tier2")

    def test_individual_and_batch_dual_alert(self) -> None:
        """CVE matching both an individual and a batch product gets both."""
        from ccc.runner import run_once
        t0 = utc("2026-07-01T00:00:00")
        # CPE list contains BOTH product triples.
        cve = NvdCve(
            cve_id="CVE-2026-5001",
            published=t0,
            last_modified=t0 + timedelta(hours=1),
            vuln_status="Analyzed",
            description="dual",
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N",
            cpes=[
                CpeMatch(cpe="cpe:2.3:a:acme:prod_app:*", vulnerable=True),
                CpeMatch(cpe="cpe:2.3:a:acme:weekly_app:*", vulnerable=True),
            ],
        )

        class FakeNvdClient:
            def __init__(self, api_key=None, **kwargs):
                self._cves = [cve]

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetch_window(self, start, end):
                return self._cves

        alert_mock = MagicMock()
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_alert", alert_mock),
            patch("ccc.runner.send_digest_alert"),
        ):
            _FakeDatetime._now = t0
            cfg = _cfg(self.tmpdir)
            report = run_once(cfg, [self.weekly, self.individual], dry_run=False)

        # Individual alert sent NOW; batch line queued (not sent until due).
        self.assertEqual(alert_mock.call_count, 1)
        self.assertEqual(report.sent, 1)
        self.assertEqual(len(self._pending()["tier3"]["entries"]), 1)

    def test_flush_passes_accent_color_to_digest(self) -> None:
        """The flush forwards the product's category accent_color."""
        from ccc.runner import run_once
        t0 = utc("2026-07-01T00:00:00")
        cve = _cve("CVE-2026-6001", "weekly_app", t0)
        accented = build_product(
            "Weekly App", "cpe:2.3:a:acme:weekly_app:*",
            alert_mode="batch", batch_period="weekly",
            accent_color="#cc0000", category="tier3",
        )

        class FakeNvdClient:
            def __init__(self, api_key=None, **kwargs):
                self._cves = [cve]

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetch_window(self, start, end):
                return self._cves

        digest_mock = MagicMock()
        # Run 1: enqueue.
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", digest_mock),
            patch("ccc.runner.send_alert"),
        ):
            _FakeDatetime._now = t0
            run_once(_cfg(self.tmpdir), [accented], dry_run=False)
        digest_mock.assert_not_called()

        # Run 2: flush due -> accent_color forwarded.
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", digest_mock),
            patch("ccc.runner.send_alert"),
        ):
            _FakeDatetime._now = t0 + timedelta(days=8)
            run_once(_cfg(self.tmpdir), [accented], dry_run=False)

        self.assertEqual(digest_mock.call_count, 1)
        self.assertEqual(digest_mock.call_args.kwargs.get("accent_color"), "#cc0000")
        self.assertEqual(digest_mock.call_args.kwargs.get("category"), "tier3")

    def test_multiple_products_one_tier_one_digest_card(self) -> None:
        """Two products in the same tier flush as ONE digest, grouped by product."""
        from ccc.runner import run_once
        t0 = utc("2026-07-01T00:00:00")
        prod_a = build_product(
            "Product A", "cpe:2.3:a:acme:prod_a:*",
            alert_mode="batch", batch_period="weekly", category="tier3",
        )
        prod_b = build_product(
            "Product B", "cpe:2.3:a:acme:prod_b:*",
            alert_mode="batch", batch_period="weekly", category="tier3",
        )
        cve_a1 = _cve("CVE-2026-7001", "prod_a", t0)
        cve_a2 = _cve("CVE-2026-7002", "prod_a", t0)
        cve_b1 = _cve("CVE-2026-7003", "prod_b", t0)

        class FakeNvdClient:
            def __init__(self, api_key=None, **kwargs):
                self._cves = [cve_a1, cve_a2, cve_b1]

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetch_window(self, start, end):
                return self._cves

        digest_mock = MagicMock()
        # Run 1: enqueue all 3 CVEs into the single tier3 bucket.
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", digest_mock),
            patch("ccc.runner.send_alert"),
        ):
            _FakeDatetime._now = t0
            run_once(_cfg(self.tmpdir), [prod_a, prod_b], dry_run=False)
        digest_mock.assert_not_called()
        self.assertEqual(len(self._pending()["tier3"]["entries"]), 3)

        # Run 2: flush -> exactly ONE digest for the whole tier.
        with (
            patch("ccc.runner.NvdClient", FakeNvdClient),
            patch("ccc.runner.datetime", _FakeDatetime),
            patch("ccc.runner.fetch_epss", return_value={}),
            patch("ccc.runner.send_digest_alert", digest_mock),
            patch("ccc.runner.send_alert"),
        ):
            _FakeDatetime._now = t0 + timedelta(days=8)
            run_once(_cfg(self.tmpdir), [prod_a, prod_b], dry_run=False)

        self.assertEqual(digest_mock.call_count, 1, "one tier -> one digest card")
        args = digest_mock.call_args
        self.assertEqual(args[0][1], "tier3")  # tier name, not product name
        entries = args[0][2]
        by_cve = {e["cve_id"]: e for e in entries}
        self.assertEqual(by_cve["CVE-2026-7001"]["products"], ["Product A"])
        self.assertEqual(by_cve["CVE-2026-7003"]["products"], ["Product B"])


if __name__ == "__main__":
    unittest.main()
