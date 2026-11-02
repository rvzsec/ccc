# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Bridge feed-extracted CVE IDs to NVD/KEV/EPSS signal.

When a feed entry (e.g. a GitLab security release) names CVE IDs, we look them
up so the alert carries real CVSS/KEV/EPSS instead of just a title + link.

Everything here is BEST-EFFORT: any lookup failure degrades to partial or empty
signal and never blocks the feed alert. CVSS results are cached on disk
(feed_cve_cache.json) so a release that lingers in the feed is not re-queried
every poll - NVD's single-CVE endpoint is paced at 6s/request.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ccc._logging import log
from ccc.enrich import EnrichError, fetch_epss, fetch_kev
from ccc.nvd import NvdClient, NvdError
from ccc.state import _atomic_write

# Cap enrichment per entry so a release listing 30 CVEs doesn't stall the run
# on paced NVD calls. The rest still appear in the card as bare IDs.
MAX_ENRICH_PER_ENTRY = 15


@dataclass
class CveSignal:
    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    kev: bool = False
    kev_name: str = ""
    epss: float | None = None
    enriched: bool = False  # True once NVD/KEV/EPSS data was attached


def enrich_cves(
    cve_ids: list[str],
    state_dir: Path,
    nvd_api_key: str | None = None,
) -> list[CveSignal]:
    """Return a CveSignal per id (order-stable, de-duplicated).

    Failures are swallowed with a warning; the returned signals simply carry
    whatever we managed to resolve.
    """
    unique: list[str] = []
    for c in cve_ids:
        if c not in unique:
            unique.append(c)
    if not unique:
        return []

    # KEV (membership + curated name), cached 6h on disk. Best-effort.
    kev_map: dict[str, str] = {}
    try:
        kev_map = fetch_kev(state_dir)
    except EnrichError as e:
        log.warning("feed enrich: KEV unavailable (%s)", e)

    # EPSS batch lookup. Best-effort (returns {} on failure internally).
    epss_map = fetch_epss(unique)

    # CVSS from on-disk cache first, then NVD single-CVE lookups (paced).
    cache = _load_cve_cache(state_dir)
    to_fetch = [c for c in unique[:MAX_ENRICH_PER_ENTRY] if c not in cache]
    if to_fetch:
        try:
            with NvdClient(api_key=nvd_api_key) as client:
                for cve_id in to_fetch:
                    try:
                        rec = client.fetch_cve(cve_id)
                    except NvdError as e:
                        log.warning("feed enrich: NVD lookup failed for %s (%s)", cve_id, e)
                        continue
                    if rec is None:
                        cache[cve_id] = {"cvss": None, "severity": None, "vector": None}
                    else:
                        cache[cve_id] = {
                            "cvss": rec.cvss_score,
                            "severity": rec.cvss_severity,
                            "vector": rec.cvss_vector,
                        }
        finally:
            _save_cve_cache(state_dir, cache)

    out: list[CveSignal] = []
    for cve_id in unique:
        cached = cache.get(cve_id) or {}
        sig = CveSignal(
            cve_id=cve_id,
            cvss_score=cached.get("cvss"),
            cvss_severity=cached.get("severity"),
            cvss_vector=cached.get("vector"),
            kev=cve_id in kev_map,
            kev_name=kev_map.get(cve_id, ""),
            epss=epss_map.get(cve_id),
        )
        sig.enriched = (
            sig.cvss_score is not None or sig.kev or sig.epss is not None
        )
        out.append(sig)
    return out


# ---------- cache ----------

def _load_cve_cache(state_dir: Path) -> dict[str, dict]:
    path = state_dir / "feed_cve_cache.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return {}


def _save_cve_cache(state_dir: Path, cache: dict[str, dict]) -> None:
    cache["_meta"] = {"written_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(state_dir / "feed_cve_cache.json", json.dumps(cache, indent=2, sort_keys=True))
    except OSError as e:
        log.warning("feed_cve_cache write failed: %s", e)
