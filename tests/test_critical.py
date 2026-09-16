"""Critical-path tests for the modules Oracle flagged as untested:
resolver, nvd._normalize, enrich (KEV stale fallback), config validators.

Kept as unittest.TestCase to match the existing test_dedup.py style; runs
under `python -m unittest discover`.
"""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock


# ============================================================
# resolver.py  - token scoring, ambiguity, deprecated fallback
# ============================================================

class ResolverTokenizeTest(unittest.TestCase):
    def test_tokenize_strips_short_and_punctuation(self) -> None:
        from ccc.resolver import _tokenize
        self.assertEqual(_tokenize("apache log4j"), {"apache", "log4j"})
        self.assertEqual(_tokenize("a-b cisco_asa"), {"cisco", "asa"})
        self.assertEqual(_tokenize(""), set())

    def test_tokenize_drops_single_char(self) -> None:
        from ccc.resolver import _tokenize
        # 'a' must be dropped (would match too many CPEs).
        self.assertNotIn("a", _tokenize("a apache"))


class ResolverWildcardTest(unittest.TestCase):
    def test_wildcardize_version_collapses_version_slot(self) -> None:
        from ccc.resolver import _wildcardize_version
        self.assertEqual(
            _wildcardize_version("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
            "cpe:2.3:a:apache:log4j:*",
        )

    def test_wildcardize_preserves_specific_update_slot(self) -> None:
        # If the update slot is non-wildcard, keep enough of the tail to disambiguate
        from ccc.resolver import _wildcardize_version
        result = _wildcardize_version("cpe:2.3:a:vendor:product:1.0:beta:*:*:*:*:*:*")
        self.assertTrue(result.startswith("cpe:2.3:a:vendor:product:*:beta"))


class ResolverScoringTest(unittest.TestCase):
    """Verify the vote-based scoring picks the right CPE when NVD returns many."""

    def _fake_response(self, candidates: list[dict]) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"products": candidates}
        return resp

    def test_picks_winner_when_one_canonical_dominates(self) -> None:
        from ccc.resolver import _resolve_one
        # 5 version-pinned log4j entries + 1 unrelated. All log4j vote for the same
        # wildcarded canonical CPE -> winner.
        cands = [
            {"cpe": {"cpeName": f"cpe:2.3:a:apache:log4j:2.{i}:*:*:*:*:*:*:*",
                     "deprecated": False}}
            for i in range(5)
        ]
        cands.append({"cpe": {"cpeName": "cpe:2.3:a:apache:tomcat:*",
                              "deprecated": False}})
        client = MagicMock()
        client.get.return_value = self._fake_response(cands)
        result = _resolve_one(client, "apache log4j")
        self.assertEqual(result, "cpe:2.3:a:apache:log4j:*")

    def test_ambiguous_names_raise(self) -> None:
        from ccc.resolver import _resolve_one, ResolveError
        # Two distinct products tied at equal token overlap.
        cands = [
            {"cpe": {"cpeName": "cpe:2.3:a:microsoft:exchange_server:*",
                     "deprecated": False}},
            {"cpe": {"cpeName": "cpe:2.3:a:microsoft:exchange_messenger:*",
                     "deprecated": False}},
        ]
        client = MagicMock()
        client.get.return_value = self._fake_response(cands)
        with self.assertRaises(ResolveError) as ctx:
            _resolve_one(client, "microsoft exchange")
        self.assertIn("ambiguous", str(ctx.exception))

    def test_deprecated_fallback_when_all_deprecated(self) -> None:
        from ccc.resolver import _resolve_one
        # Jenkins has only deprecated entries post-NVD-consolidation.
        cands = [
            {"cpe": {"cpeName": "cpe:2.3:a:cloudbees:jenkins:*",
                     "deprecated": True}},
        ]
        client = MagicMock()
        client.get.return_value = self._fake_response(cands)
        # Should fall back instead of raising.
        result = _resolve_one(client, "jenkins")
        self.assertEqual(result, "cpe:2.3:a:cloudbees:jenkins:*")

    def test_malformed_products_field_raises(self) -> None:
        """S1 regression: NVD returns 'products' as a string -> ResolveError, no crash."""
        from ccc.resolver import _resolve_one, ResolveError
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"products": "not-a-list"}
        client = MagicMock()
        client.get.return_value = resp
        with self.assertRaises(ResolveError):
            _resolve_one(client, "anything")

    def test_empty_products_raises(self) -> None:
        from ccc.resolver import _resolve_one, ResolveError
        client = MagicMock()
        client.get.return_value = self._fake_response([])
        with self.assertRaises(ResolveError) as ctx:
            _resolve_one(client, "nonexistent")
        self.assertIn("no CPEs match", str(ctx.exception))

    def test_skips_non_dict_entries_in_products_list(self) -> None:
        """S1: defensive iteration over malformed entries."""
        from ccc.resolver import _resolve_one
        cands = [
            "not-a-dict",  # malformed
            42,            # malformed
            {"cpe": {"cpeName": "cpe:2.3:a:apache:log4j:*",
                     "deprecated": False}},
        ]
        client = MagicMock()
        client.get.return_value = self._fake_response(cands)
        result = _resolve_one(client, "apache log4j")
        self.assertEqual(result, "cpe:2.3:a:apache:log4j:*")


class ResolverCacheTest(unittest.TestCase):
    """Verify on-disk cache round-trips + corruption tolerance."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-resolver-test-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cache_roundtrip(self) -> None:
        from ccc.resolver import _save_cache, _load_cache
        cache_file = self.tmpdir / "cpe_cache.json"
        original = {"jenkins": "cpe:2.3:a:cloudbees:jenkins:*"}
        _save_cache(cache_file, original)
        loaded = _load_cache(cache_file)
        self.assertEqual(loaded, original)

    def test_cache_corruption_returns_empty(self) -> None:
        from ccc.resolver import _load_cache
        cache_file = self.tmpdir / "cpe_cache.json"
        cache_file.write_text("{not valid json", encoding="utf-8")
        self.assertEqual(_load_cache(cache_file), {})

    def test_cache_missing_returns_empty(self) -> None:
        from ccc.resolver import _load_cache
        self.assertEqual(_load_cache(self.tmpdir / "missing.json"), {})


# ============================================================
# nvd.py  -  _normalize, CWE extraction, CVSS picking
# ============================================================

class NvdNormalizeTest(unittest.TestCase):
    def _make_cve_blob(self, **overrides) -> dict:
        base = {
            "id": "CVE-2024-1234",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "test description"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N",
                    }
                }]
            },
            "configurations": [],
            "references": [],
        }
        base.update(overrides)
        return base

    def test_normalize_basic(self) -> None:
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob())
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2024-1234")
        self.assertEqual(cve.cvss_score, 9.8)
        self.assertEqual(cve.cvss_severity, "CRITICAL")

    def test_normalize_drops_rejected(self) -> None:
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(vulnStatus="Rejected"))
        self.assertIsNone(cve)

    def test_normalize_handles_missing_cvss(self) -> None:
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(metrics={}))
        self.assertIsNotNone(cve)
        self.assertIsNone(cve.cvss_score)
        self.assertIsNone(cve.cvss_severity)

    def test_normalize_prefers_v31_over_v30(self) -> None:
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(metrics={
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        }))
        self.assertEqual(cve.cvss_score, 9.0)

    def test_normalize_reads_v40_only_cve(self) -> None:
        """Regression: a CVE carrying ONLY cvssMetricV40 must get its score
        and vector, not be silently dropped by the gate."""
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(metrics={
            "cvssMetricV40": [{
                "cvssData": {
                    "baseScore": 9.3,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                }
            }],
        }))
        self.assertEqual(cve.cvss_score, 9.3)
        self.assertEqual(cve.cvss_severity, "CRITICAL")
        self.assertEqual(
            cve.cvss_vector,
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
        )

    def test_normalize_prefers_v31_over_v40(self) -> None:
        """v3.1 stays primary so existing CVEs keep their current score."""
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(metrics={
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
        }))
        self.assertEqual(cve.cvss_score, 9.8)

    def test_normalize_prefers_v40_over_v30_and_v2(self) -> None:
        from ccc.nvd import _normalize
        cve = _normalize(self._make_cve_blob(metrics={
            "cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM"}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 4.0}}],
        }))
        self.assertEqual(cve.cvss_score, 8.7)

    def test_extract_cwes_drops_sentinels(self) -> None:
        from ccc.nvd import _extract_cwes
        weaknesses = [
            {"description": [{"value": "CWE-502"}, {"value": "CWE-noinfo"}]},
            {"description": [{"value": "CWE-Other"}]},
            {"description": [{"value": "CWE-20"}]},
        ]
        result = _extract_cwes(weaknesses)
        self.assertEqual(result, ["CWE-502", "CWE-20"])
        self.assertNotIn("CWE-noinfo", result)
        self.assertNotIn("CWE-Other", result)

    def test_extract_cpes_only_vulnerable(self) -> None:
        from ccc.nvd import _extract_cpes
        configs = [{
            "nodes": [{
                "cpeMatch": [
                    {"criteria": "cpe:2.3:a:vendor:vuln_product:*", "vulnerable": True},
                    {"criteria": "cpe:2.3:a:vendor:safe_product:*", "vulnerable": False},
                ]
            }]
        }]
        cpes = list(_extract_cpes(configs))
        self.assertEqual(len(cpes), 2)  # Both extracted; matcher filters
        vulnerable = [c for c in cpes if c.vulnerable]
        self.assertEqual(len(vulnerable), 1)
        self.assertEqual(vulnerable[0].cpe, "cpe:2.3:a:vendor:vuln_product:*")


# ============================================================
# config.py  -  CPE regex, extra=forbid, severity floor
# ============================================================

class ConfigValidatorTest(unittest.TestCase):
    def test_cpe_regex_accepts_valid(self) -> None:
        from ccc.config import Product
        p = Product(name="test", cpe="cpe:2.3:a:apache:log4j:*")
        self.assertEqual(p.name, "test")

    def test_cpe_regex_rejects_invalid(self) -> None:
        from ccc.config import Product
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            Product(name="test", cpe="not-a-cpe")

    def test_cpe_regex_rejects_bad_part_slot(self) -> None:
        from ccc.config import Product
        from pydantic import ValidationError
        # CPE part slot must be a, o, or h
        with self.assertRaises(ValidationError):
            Product(name="test", cpe="cpe:2.3:x:apache:log4j:*")

    def test_cpe_triple_lowercases_part(self) -> None:
        from ccc.config import Product
        # The CPE regex rejects uppercase part slot at validation time.
        # cpe_triple() lowercases when NVD returns one mid-flight - tested in matcher tests.
        p = Product(name="test", cpe="cpe:2.3:a:apache:log4j:*")
        triple = p.cpe_triple()
        self.assertEqual(triple, ("a", "apache", "log4j"))

    def test_severity_floor_score_mapping(self) -> None:
        from ccc.config import Config, SEVERITY_SCORES
        cfg = Config(
            google_chat_webhook="https://chat.googleapis.com/v1/spaces/X/messages?key=k&token=t",
            severity_floor="critical",
        )
        self.assertEqual(cfg.severity_floor_score(), SEVERITY_SCORES["critical"])
        self.assertEqual(cfg.severity_floor_score(), 9.0)


# ============================================================
# enrich.py  -  KEV cache + stale fallback + EPSS chunking
# ============================================================

class EnrichKevCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="ccc-enrich-test-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fresh_cache_hit_returns_data(self) -> None:
        from ccc.enrich import fetch_kev
        cache_file = self.tmpdir / "kev.json"
        cache_file.write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "names": {"CVE-2021-44228": "Apache Log4j2 RCE"},
        }), encoding="utf-8")
        result = fetch_kev(self.tmpdir)
        self.assertEqual(result.get("CVE-2021-44228"), "Apache Log4j2 RCE")

    def test_stale_cache_with_network_failure_falls_back(self) -> None:
        """F2 + Oracle scenario 4: KEV outage falls back to stale cache."""
        from ccc.enrich import fetch_kev
        cache_file = self.tmpdir / "kev.json"
        cache_file.write_text(json.dumps({
            "fetched_at": "2020-01-01T00:00:00",
            "names": {"CVE-2020-0001": "Old KEV Entry"},
        }), encoding="utf-8")
        # Force the cache to look stale by backdating its mtime.
        old_mtime = time.time() - 10 * 3600  # 10 hours ago, beyond the 6h TTL
        import os
        os.utime(cache_file, (old_mtime, old_mtime))

        # Mock the network call to fail.
        with patch("ccc.enrich.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            import httpx
            mock_client.get.side_effect = httpx.HTTPError("simulated")
            mock_client_cls.return_value = mock_client
            # Should NOT raise; should return the stale data.
            result = fetch_kev(self.tmpdir)
            self.assertEqual(result.get("CVE-2020-0001"), "Old KEV Entry")

    def test_no_cache_no_network_raises(self) -> None:
        """F2: KEV fetch with NO cache + network failure raises EnrichError."""
        from ccc.enrich import fetch_kev, EnrichError
        with patch("ccc.enrich.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = False
            import httpx
            mock_client.get.side_effect = httpx.HTTPError("simulated")
            mock_client_cls.return_value = mock_client
            with self.assertRaises(EnrichError):
                fetch_kev(self.tmpdir)


class EnrichEpssChunkingTest(unittest.TestCase):
    def test_epss_batches_at_100_cves(self) -> None:
        """EPSS API has a query-string length limit; we chunk at 100."""
        from ccc.enrich import _chunked, EPSS_BATCH_SIZE
        cves = [f"CVE-2024-{i:04d}" for i in range(250)]
        chunks = _chunked(cves, EPSS_BATCH_SIZE)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(len(chunks[0]), 100)
        self.assertEqual(len(chunks[1]), 100)
        self.assertEqual(len(chunks[2]), 50)


# ============================================================
# cwe.py  -  the new module from Item 5
# ============================================================

class CweLookupTest(unittest.TestCase):
    def test_known_cwe_returns_short_name(self) -> None:
        from ccc.cwe import lookup
        self.assertEqual(lookup("CWE-502"), "Deserialization of Untrusted Data")

    def test_unknown_cwe_returns_none(self) -> None:
        from ccc.cwe import lookup
        self.assertIsNone(lookup("CWE-9999999"))

    def test_table_is_a_dict_of_str_to_str(self) -> None:
        from ccc.cwe import CWE_NAMES
        for k, v in CWE_NAMES.items():
            self.assertTrue(k.startswith("CWE-"))
            self.assertIsInstance(v, str)


if __name__ == "__main__":
    unittest.main()
