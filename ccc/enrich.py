# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Signal enrichment - EPSS (FIRST.org) + CISA KEV.

EPSS: exploit-prediction score, 0.0 to 1.0. Higher = more likely to be
      exploited in the next 30 days.
      API: https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...   (batch up to ~100)

KEV : CISA Known Exploited Vulnerabilities catalog. If a CVE is here, it's
      being actively exploited in the wild - we bypass the severity floor.
      JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      Single file ~500KB. Cache on disk 6h to be polite.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ccc._logging import log

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEV_CACHE_SECONDS = 6 * 3600
EPSS_BATCH_SIZE = 100


class EnrichError(Exception):
    """Enrichment failed - non-fatal, we proceed with empty data."""


# ---------- EPSS ----------

def fetch_epss(cve_ids: list[str], timeout: float = 20.0) -> dict[str, float]:
    """Return {cve_id: epss_score}. Missing CVEs are simply absent."""
    if not cve_ids:
        return {}
    result: dict[str, float] = {}
    with httpx.Client(timeout=timeout, headers={"Accept": "application/json"}) as client:
        for chunk in _chunked(cve_ids, EPSS_BATCH_SIZE):
            params = {"cve": ",".join(chunk)}
            try:
                resp = client.get(EPSS_URL, params=params)
                resp.raise_for_status()
                payload = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                # Enrichment failures are non-fatal. Log and move on.
                log.warning("EPSS fetch failed: %s", e)
                continue
            for row in payload.get("data") or []:
                cve = row.get("cve")
                score = row.get("epss")
                if cve and score is not None:
                    try:
                        result[cve] = float(score)
                    except (TypeError, ValueError):
                        continue
    return result


# ---------- KEV ----------

def fetch_kev(cache_dir: Path, timeout: float = 30.0) -> dict[str, str]:
    """Return {cve_id: vulnerabilityName} from CISA KEV. Cached 6h on disk.

    CISA ships a clean human title per KEV entry (e.g. "Apache Log4j2 Remote
    Code Execution Vulnerability") that we use as the alert title when present.
    Membership-only callers can do `cve_id in result`.

    On fetch failure with NO usable cache: raises EnrichError. Caller must
    treat this as fatal so last_run is not advanced - otherwise a KEV-only
    CVE would silently miss its alert window forever.

    On fetch failure WITH a stale-but-readable cache: returns the stale data
    with a warning. Better an hour-old KEV list than no KEV list.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "kev.json"
    cached = _read_kev_cache(cache_file)
    if cached is not None:
        return cached

    with httpx.Client(
        timeout=timeout,
        headers={"Accept": "application/json", "User-Agent": "ccc/0.1"},
    ) as client:
        try:
            resp = client.get(KEV_URL)
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            stale = _read_kev_cache_stale(cache_file)
            if stale is not None:
                log.warning("KEV fetch failed (%s); using stale on-disk cache", e)
                return stale
            raise EnrichError(
                f"KEV fetch failed and no cache available: {e}. "
                "Refusing to run without KEV data (would silently disable KEV bypass)."
            ) from e

    names: dict[str, str] = {}
    for v in payload.get("vulnerabilities") or []:
        cve = v.get("cveID")
        if cve:
            names[cve] = (v.get("vulnerabilityName") or "").strip()

    _write_kev_cache(cache_file, names)
    return names


def _read_kev_cache(path: Path) -> dict[str, str] | None:
    """Return cached KEV data if fresh (within KEV_CACHE_SECONDS), else None."""
    if not path.exists():
        return None
    try:
        mtime = path.stat().st_mtime
        if time.time() - mtime > KEV_CACHE_SECONDS:
            return None
        return _parse_kev_cache(path)
    except OSError:
        return None


def _read_kev_cache_stale(path: Path) -> dict[str, str] | None:
    """Read KEV cache ignoring TTL. Fallback for fetch failures."""
    if not path.exists():
        return None
    try:
        return _parse_kev_cache(path)
    except OSError:
        return None


def _parse_kev_cache(path: Path) -> dict[str, str] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    names = data.get("names")
    if isinstance(names, dict):
        return {k: str(v) for k, v in names.items()}
    # Back-compat with older cache that only stored IDs.
    ids = data.get("ids")
    if isinstance(ids, list):
        return {cve: "" for cve in ids}
    return None


def _write_kev_cache(path: Path, names: dict[str, str]) -> None:
    try:
        path.write_text(
            json.dumps(
                {
                    "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "names": names,
                }
            ),
            encoding="utf-8",
        )
    except OSError as e:
        log.warning("KEV cache write failed: %s", e)


# ---------- utils ----------

def _chunked(xs: list[str], n: int) -> list[list[str]]:
    return [xs[i:i + n] for i in range(0, len(xs), n)]
