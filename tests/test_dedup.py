"""Dedup correctness test - runs BEFORE any network code is written.

Simulates 24 hourly cron ticks. For each tick:
  - Compute the (start, end) window via state.compute_window
  - Pretend a fixed set of CVEs exists in NVD, each with a lastModified date
  - For each CVE in the window, call check_and_mark
  - Record every (True, _) decision as an "alert sent"
  - Update last_run after the tick

Assertions:
  - No CVE is alerted twice unless its alert-hash changed
  - When NVD modifies a CVE (hash changes), exactly one [UPDATED] alert fires
  - A 10-min cron overrun does NOT produce duplicate alerts
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ccc.state import (
    check_and_mark,
    compute_window,
    load_recent,
    read_last_run,
    save_recent,
    write_last_run,
)


def utc(s: str) -> datetime:
    """Helper: parse a fixed-format UTC timestamp."""
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


# Simulated NVD database. Each entry: (cve_id, lastModified, cvss, kev, epss, status)
# CVE-9999-A: published once, never modified
# CVE-9999-B: published once, modified mid-day (cvss bumped)
# CVE-9999-C: published mid-day, never modified
# CVE-9999-D: KEV-listed mid-day (kev flag flips from False to True)
SIMULATED_NVD = [
    # Tick 0 baseline
    ("CVE-9999-A", utc("2025-01-01T05:30:00"), 7.5, False, 0.1, "Analyzed"),
    ("CVE-9999-B", utc("2025-01-01T05:45:00"), 6.0, False, 0.1, "Analyzed"),
    # B gets CVSS bumped at hour 12
    ("CVE-9999-B", utc("2025-01-01T12:15:00"), 9.1, False, 0.1, "Modified"),
    # C published mid-day
    ("CVE-9999-C", utc("2025-01-01T14:30:00"), 8.0, False, 0.2, "Analyzed"),
    # D added to KEV at hour 18
    ("CVE-9999-D", utc("2025-01-01T03:00:00"), 5.0, False, 0.0, "Analyzed"),
    ("CVE-9999-D", utc("2025-01-01T18:20:00"), 5.0, True, 0.7, "Analyzed"),
]


def nvd_query(start: datetime, end: datetime) -> list[tuple]:
    """Return all simulated CVEs whose lastModified falls in [start, end)."""
    return [entry for entry in SIMULATED_NVD if start <= entry[1] < end]


class DedupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-test-"))

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_tick(self, tick_start: datetime) -> list[tuple[str, bool]]:
        """Simulate one cron run. Returns list of (cve_id, is_update) alerts."""
        # 1. compute window with 10-min overlap, 24h max lookback
        start, end = compute_window(
            self.tmpdir, tick_start, overlap_minutes=10, max_lookback_hours=24
        )
        # 2. fetch from simulated NVD
        rows = nvd_query(start, end)
        # 3. load recent hash cache
        recent = load_recent(self.tmpdir)
        # 4. for each CVE: dedup-check, collect alerts
        alerts: list[tuple[str, bool]] = []
        for cve_id, _last_mod, cvss, kev, epss, status in rows:
            should_alert, is_update = check_and_mark(
                recent, cve_id, cvss, kev, epss, status, tick_start
            )
            if should_alert:
                alerts.append((cve_id, is_update))
        # 5. on success, persist
        save_recent(self.tmpdir, recent, tick_start)
        write_last_run(self.tmpdir, tick_start)
        return alerts

    def test_24_hourly_ticks_no_dupes(self) -> None:
        """24 ticks. A,C alerted once. B alerted twice (once new, once UPDATED).
        D alerted twice (once new, once UPDATED for KEV addition).
        """
        base = utc("2025-01-01T00:00:00")
        all_alerts: dict[str, list[bool]] = {}
        for hour in range(24):
            tick = base + timedelta(hours=hour)
            for cve_id, is_update in self._run_tick(tick):
                all_alerts.setdefault(cve_id, []).append(is_update)

        # CVE-A: appears once (hour 5), never modified → alerted exactly once, not UPDATED
        self.assertEqual(all_alerts.get("CVE-9999-A"), [False], "CVE-A should fire once new")

        # CVE-B: hour 5 new + hour 12 UPDATED = 2 alerts
        self.assertEqual(
            all_alerts.get("CVE-9999-B"),
            [False, True],
            "CVE-B should fire as new then UPDATED",
        )

        # CVE-C: hour 14 new = 1 alert
        self.assertEqual(all_alerts.get("CVE-9999-C"), [False])

        # CVE-D: hour 3 new (kev=False) + hour 18 UPDATED (kev=True) = 2 alerts
        self.assertEqual(all_alerts.get("CVE-9999-D"), [False, True])

    def test_cron_overrun_hash_cache_catches_dupe(self) -> None:
        """Two ticks where tick 2's WINDOW genuinely re-includes a CVE that
        tick 1 already alerted on. This exercises L3 (hash cache), not L2
        (window math). Oracle audit J1.

        Setup: CVE-X has lastModified at 5:55. Tick 1 runs at 6:00 with last_run
        empty -> window is (5:00, 6:00) -> CVE-X in range, alerted.
        Tick 2 runs at 6:05 with last_run=6:00 -> window is (5:50, 6:05) ->
        CVE-X still in range (NVD would return it again). Only the hash cache
        stops the dup.
        """
        # Override SIMULATED_NVD locally for this test.
        local_db = [
            ("CVE-OVERRUN-1", utc("2025-01-01T05:55:00"), 9.0, False, 0.3, "Analyzed"),
        ]

        def local_query(start: datetime, end: datetime) -> list[tuple]:
            return [e for e in local_db if start <= e[1] < end]

        def run(tick_start: datetime) -> list[tuple[str, bool]]:
            start, end = compute_window(
                self.tmpdir, tick_start, overlap_minutes=10, max_lookback_hours=24
            )
            recent = load_recent(self.tmpdir)
            alerts: list[tuple[str, bool]] = []
            for cve_id, _lm, cvss, kev, epss, status in local_query(start, end):
                should_alert, is_update = check_and_mark(
                    recent, cve_id, cvss, kev, epss, status, tick_start
                )
                if should_alert:
                    alerts.append((cve_id, is_update))
            save_recent(self.tmpdir, recent, tick_start)
            write_last_run(self.tmpdir, tick_start)
            return alerts

        a1 = run(utc("2025-01-01T06:00:00"))
        a2 = run(utc("2025-01-01T06:05:00"))

        self.assertEqual(a1, [("CVE-OVERRUN-1", False)],
                         "tick 1 should fire a fresh alert")
        self.assertEqual(a2, [],
                         "tick 2's window re-includes CVE-X but L3 hash cache "
                         "must drop it (this is what the audit flagged)")


class CpeCaseMismatchTest(unittest.TestCase):
    """Oracle audit C1+C2+J4: NVD sometimes ships mixed-case CPEs. The matcher
    must lowercase both sides for triple + version-pin comparisons."""

    def _make_cve(self, cve_cpe: str) -> Any:
        from ccc.nvd import CpeMatch, NvdCve
        return NvdCve(
            cve_id="CVE-TEST-CASE",
            published=utc("2025-01-01T00:00:00"),
            last_modified=utc("2025-01-01T00:00:00"),
            vuln_status="Analyzed",
            description="test",
            cvss_score=9.0,
            cvss_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N",
            cpes=[CpeMatch(cpe=cve_cpe, vulnerable=True)],
        )

    def test_triple_match_when_nvd_uppercases_vendor(self) -> None:
        from ccc.config import Product
        from ccc.matcher import match_cve

        cve = self._make_cve("cpe:2.3:a:Apache:Log4j:2.14.1:*:*:*:*:*:*:*")
        product = Product(name="Apache Log4j", cpe="cpe:2.3:a:apache:log4j:*")
        hits = match_cve(cve, [product])
        self.assertEqual(hits, [product],
                         "triple match must work when NVD returns mixed-case CPE")

    def test_version_pin_match_when_nvd_uppercases(self) -> None:
        from ccc.config import Product
        from ccc.matcher import match_cve

        cve = self._make_cve("cpe:2.3:a:Apache:Log4j:2.14.1:Update1:*:*:*:*:*:*")
        product = Product(
            name="Apache Log4j 2.14.1",
            cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        )
        hits = match_cve(cve, [product])
        self.assertEqual(hits, [product],
                         "version-pin match must lowercase both sides")

    def test_part_slot_case_insensitive(self) -> None:
        from ccc.config import Product
        from ccc.matcher import match_cve

        # Edge case: NVD ships "A" instead of "a" for the part slot.
        cve = self._make_cve("cpe:2.3:A:apache:log4j:*:*:*:*:*:*:*:*")
        product = Product(name="Apache Log4j", cpe="cpe:2.3:a:apache:log4j:*")
        hits = match_cve(cve, [product])
        self.assertEqual(hits, [product],
                         "part slot case mismatch must not break the triple")


class NotifierTest(unittest.TestCase):
    """Oracle audit J5+J6: dry-run must not crash; HTML escape must work."""

    def _sample_match(self, description: str = "test", products: list | None = None):
        from ccc.config import Product
        from ccc.matcher import Match
        from ccc.nvd import CpeMatch, NvdCve
        cve = NvdCve(
            cve_id="CVE-2099-0001",
            published=utc("2025-01-01T00:00:00"),
            last_modified=utc("2025-01-01T00:00:00"),
            vuln_status="Analyzed",
            description=description,
            cvss_score=9.8,
            cvss_severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N",
            cpes=[CpeMatch(cpe="cpe:2.3:a:acme:widget:*", vulnerable=True)],
        )
        prods = products or [Product(name="Acme Widget", cpe="cpe:2.3:a:acme:widget:*")]
        return Match(cve=cve, products=prods, epss=0.5, kev=False, kev_name="")

    def test_dry_run_does_not_crash_with_real_match(self) -> None:
        """Regression: payload has no top-level 'text' key but dry-run used to
        print payload['text']. Oracle audit D6/J5."""
        from ccc.notifier import send_alert
        # Should NOT raise. Uses fake URL because dry_run skips network.
        send_alert("http://unused", self._sample_match(), is_update=False, dry_run=True)

    def test_html_in_description_is_escaped(self) -> None:
        """Untrusted NVD description must not be rendered as HTML.
        Oracle audit D1/J6."""
        from ccc.notifier import _build_payload
        malicious = '</font><a href="https://attacker.example">click</a>'
        match = self._sample_match(description=malicious)
        payload = _build_payload(match, is_update=False)
        body = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["textParagraph"]["text"]
        self.assertNotIn('<a href="https://attacker.example"', body,
                         "raw attacker HTML must not appear in the card body")
        self.assertIn("&lt;", body,
                      "the < character from the description must be escaped")

    def test_html_in_product_name_is_escaped(self) -> None:
        from ccc.config import Product
        from ccc.notifier import _build_payload
        sneaky_product = Product(name="AT&T <Gear>", cpe="cpe:2.3:a:acme:widget:*")
        match = self._sample_match(products=[sneaky_product])
        payload = _build_payload(match, is_update=False)
        body = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["textParagraph"]["text"]
        self.assertIn("AT&amp;T", body)
        self.assertIn("&lt;Gear&gt;", body)


class WindowMathTest(unittest.TestCase):
    """Window math regressions for compute_window and last_run round-trip."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-window-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fresh_state_caps_lookback(self) -> None:
        """No last_run.txt and now is far in future -> window starts at now-max_lookback."""
        far = utc("2025-06-01T00:00:00")
        start, end = compute_window(
            self.tmpdir, far, overlap_minutes=10, max_lookback_hours=24
        )
        self.assertEqual(end, far)
        self.assertEqual(start, far - timedelta(hours=24))

    def test_last_run_overlap_applied(self) -> None:
        """With last_run set, window starts at last_run - overlap."""
        last = utc("2025-01-01T12:00:00")
        write_last_run(self.tmpdir, last)
        self.assertEqual(read_last_run(self.tmpdir), last)

        now = utc("2025-01-01T13:00:00")
        start, end = compute_window(
            self.tmpdir, now, overlap_minutes=10, max_lookback_hours=24
        )
        self.assertEqual(end, now)
        self.assertEqual(start, last - timedelta(minutes=10))


if __name__ == "__main__":
    unittest.main()
