# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""CPE auto-resolution from human product names.

You write "jenkins" in products.yaml. ccc looks up the canonical CPE via
the NVD CPE Dictionary API at startup, caches it forever, and the rest
of the pipeline matches strictly by CPE (same low noise as before).

API:  https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=<name>
Docs: https://nvd.nist.gov/developers/products

Caching:
  /state/cpe_cache.json  -> {raw_name: cpe_string}
  Hits are instant, misses go to NVD once. Cache is forever (CPEs are immutable
  identifiers - vendor:product never changes). Operator can `rm cpe_cache.json`
  to re-resolve all entries.

Ambiguity:
  NVD often returns dozens of CPEs for a keyword (e.g. "apache" matches
  hundreds of projects). We pick the CPE whose `cpeName` triple
  (vendor:product) tokens BEST MATCH the user's keyword tokens, ranked by
  total CVE count (matchCount). If the top candidate is not a clear winner
  (less than 2x the score of the runner-up), we fail loud and ask the
  operator to disambiguate with a CPE override.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ccc._logging import log

NVD_CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
REQUEST_PACING = 6.0  # NVD asks for >=6s between requests


class ResolveError(Exception):
    """Resolution failed in a way that should abort startup."""


@dataclass
class Resolution:
    """The result of resolving one product name."""

    name: str             # original user-supplied name
    cpe: str              # canonical CPE 2.3 string
    source: str           # "cache" | "nvd" | "override"


# ---------- cache ----------

def _load_cache(cache_file: Path) -> dict[str, str]:
    if not cache_file.exists():
        return {}
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k).lower(): str(v) for k, v in data.items()}
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return {}


def _save_cache(cache_file: Path, cache: dict[str, str]) -> None:
    """Atomically persist the resolver cache.

    Two concurrent `ccc validate` runs would otherwise race on this file;
    last writer wins and loser's NVD resolutions are dropped. The atomic
    write also prevents the truncated-file scenario when killed mid-write
    (load path tolerates it but re-resolves everything, wasting NVD quota).
    """
    # Late import: avoid a top-level cycle (state.py imports from this module
    # is theoretical but cheap to dodge by lazy-loading here).
    from ccc.state import _atomic_write

    try:
        _atomic_write(
            cache_file,
            json.dumps(cache, indent=2, sort_keys=True),
        )
    except OSError as e:
        log.warning("CPE cache write failed: %s", e)


# ---------- resolution ----------

def resolve_names(
    names: list[str],
    state_dir: Path,
    nvd_api_key: str | None = None,
    timeout: float = 30.0,
) -> list[Resolution]:
    """Resolve a list of plain product names to canonical CPEs.

    Cached lookups are instant; misses go to NVD with 6s pacing.
    Raises ResolveError if any name cannot be resolved unambiguously.
    """
    cache_file = state_dir / "cpe_cache.json"
    cache = _load_cache(cache_file)

    headers = {
        "Accept": "application/json",
        "User-Agent": "ccc/0.1 (CPE resolver)",
    }
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    out: list[Resolution] = []
    last_request_ts = 0.0
    misses_failed: list[str] = []

    with httpx.Client(timeout=timeout, headers=headers) as client:
        for raw in names:
            key = raw.strip().lower()
            if not key:
                continue

            if key in cache:
                out.append(Resolution(name=raw, cpe=cache[key], source="cache"))
                continue

            # Pace NVD requests.
            delta = time.monotonic() - last_request_ts
            if delta < REQUEST_PACING:
                time.sleep(REQUEST_PACING - delta)
            last_request_ts = time.monotonic()

            try:
                cpe = _resolve_one(client, raw)
            except ResolveError as e:
                misses_failed.append(f"{raw!r}: {e}")
                continue

            cache[key] = cpe
            out.append(Resolution(name=raw, cpe=cpe, source="nvd"))

    # Persist whatever we learned, even if some failed.
    _save_cache(cache_file, cache)

    if misses_failed:
        msg = "could not resolve product names:\n  " + "\n  ".join(misses_failed)
        msg += (
            "\n\nFix by editing products.yaml to use the full CPE string for "
            "the failing entries, e.g.:\n"
            "  - name: \"Jenkins\"\n"
            "    cpe:  \"cpe:2.3:a:jenkins_project:jenkins:*\""
        )
        raise ResolveError(msg)

    return out


def _resolve_one(client: httpx.Client, raw_name: str) -> str:
    """Query NVD for the best CPE matching raw_name."""
    params = {"keywordSearch": raw_name, "resultsPerPage": 50}
    try:
        resp = client.get(NVD_CPES_URL, params=params)
    except httpx.HTTPError as e:
        raise ResolveError(f"NVD request failed ({e})") from e

    if resp.status_code == 429:
        raise ResolveError("NVD rate limit hit (429); retry later or add nvd_api_key")
    if resp.status_code != 200:
        raise ResolveError(f"NVD HTTP {resp.status_code}: {resp.text[:200]}")

    try:
        payload = resp.json()
    except ValueError as e:
        raise ResolveError(f"NVD returned non-JSON ({e})") from e

    # Defensive: NVD outages occasionally return error pages dressed as JSON
    # with `products` as a string or scalar. Verify the shape before iterating.
    products = payload.get("products")
    if products is None:
        products = []
    if not isinstance(products, list):
        raise ResolveError(
            f"NVD returned malformed 'products' field "
            f"(expected list, got {type(products).__name__})"
        )
    if not products:
        raise ResolveError("no CPEs match this name")

    # Collapse every NVD candidate to its product-wide form (wildcard the
    # version slot) so all version-pinned variants of the same product
    # vote for one canonical CPE. Then count votes per distinct CPE.
    # Prefer non-deprecated entries; if NONE are non-deprecated (some popular
    # products like jenkins have only deprecated CPE entries post-consolidation),
    # fall back to including deprecated ones.
    votes: dict[str, int] = {}
    deprecated_votes: dict[str, int] = {}
    deprecated_fallback_used = False
    for entry in products:
        if not isinstance(entry, dict):
            continue
        cpe_obj = entry.get("cpe") or {}
        if not isinstance(cpe_obj, dict):
            continue
        cpe_name = cpe_obj.get("cpeName")
        if not isinstance(cpe_name, str) or not cpe_name:
            continue
        canonical = _wildcardize_version(cpe_name)
        if cpe_obj.get("deprecated"):
            deprecated_votes[canonical] = deprecated_votes.get(canonical, 0) + 1
        else:
            votes[canonical] = votes.get(canonical, 0) + 1

    if not votes and not deprecated_votes:
        raise ResolveError("NVD returned no parseable CPE entries")
    if not votes:
        votes = deprecated_votes
        deprecated_fallback_used = True
        # Surface the fallback so the operator knows the resolved CPE may
        # be retired by NVD. Acceptable but worth flagging.
        log.warning(
            "%r resolved via deprecated CPE entries (NVD has no non-deprecated"
            " match). Consider overriding with an explicit cpe: in products.yaml.",
            raw_name,
        )

    # Score each distinct canonical CPE by token overlap with raw name.
    name_tokens = _tokenize(raw_name)

    def score(cpe: str, vote_count: int) -> tuple[int, int, int]:
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        cpe_tokens = _tokenize(f"{vendor} {product}")
        overlap = len(name_tokens & cpe_tokens)
        extra = len(cpe_tokens - name_tokens)
        return (overlap, -extra, vote_count)

    scored = sorted(
        ((score(cpe, n), cpe) for cpe, n in votes.items()),
        reverse=True,
    )
    top_score, top_cpe = scored[0]

    if top_score[0] == 0:
        raise ResolveError(
            f"top NVD match {top_cpe!r} shares no tokens with input"
        )

    # Ambiguity: only flag if the top two candidates have IDENTICAL token
    # overlap. Vote count differentiates them otherwise.
    if len(scored) > 1:
        second_score, _ = scored[1]
        if (second_score[0] == top_score[0] and second_score[1] == top_score[1]
                and second_score[2] >= top_score[2] / 2):
            sample = [c for _, c in scored[:5]]
            raise ResolveError(
                f"ambiguous: top candidates share equal name-overlap. "
                f"Pick one and override:\n    "
                + "\n    ".join(sample)
            )

    return top_cpe


def _tokenize(s: str) -> set[str]:
    """Split a name into lowercase alphanumeric tokens."""
    tokens: set[str] = set()
    buf = []
    for ch in s.lower():
        if ch.isalnum():
            buf.append(ch)
        else:
            if buf:
                tokens.add("".join(buf))
                buf = []
    if buf:
        tokens.add("".join(buf))
    # Drop very short tokens that match anything.
    return {t for t in tokens if len(t) >= 2}


def _wildcardize_version(cpe: str) -> str:
    """Replace the version slot with * so the CPE matches any version."""
    parts = cpe.split(":")
    if len(parts) < 6:
        return cpe
    parts[5] = "*"
    # Trim trailing slots that are all '*' for cleanliness.
    while len(parts) > 6 and parts[-1] == "*":
        parts.pop()
    return ":".join(parts)
