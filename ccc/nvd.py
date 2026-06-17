"""NVD API 2.0 client.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Hard constraints from NVD:
  - date format: extended ISO-8601 with ms + offset (e.g. 2025-01-01T00:00:00.000+00:00)
  - lastModStartDate / lastModEndDate window cap: 120 days per request
  - rate limit: with API key 50 req/30s rolling, without 5 req/30s
  - NVD asks for >=6s sleep between requests as best practice; we honor it
  - pagination: resultsPerPage <= 2000, startIndex offset
  - 429 returns Retry-After header - honor it

We return a normalized dict per CVE so matcher.py doesn't have to know NVD's
shape. Anything we don't need is dropped.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD docs: 120-day window cap.
MAX_WINDOW = timedelta(days=120)
# Best-practice sleep between requests (NVD asks for >=6s).
REQUEST_PACING = 6.0
# Pagination page size.
RESULTS_PER_PAGE = 2000


@dataclass
class CpeMatch:
    """One vulnerable CPE entry from a CVE configuration."""

    cpe: str
    vulnerable: bool


@dataclass
class NvdCve:
    """Normalized CVE record."""

    cve_id: str
    published: datetime
    last_modified: datetime
    vuln_status: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None      # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cvss_vector: str | None
    cpes: list[CpeMatch] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)  # e.g. ["CWE-502", "CWE-20"]

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


# ---------- formatting ----------

def _fmt(dt: datetime) -> str:
    """NVD-accepted ISO-8601 with milliseconds + UTC offset."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # 2025-01-01T00:00:00.000+00:00
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_dt(raw: str) -> datetime:
    """Parse NVD's timestamp. They sometimes return 'Z', sometimes offset."""
    s = raw.replace("Z", "+00:00")
    # NVD ms sometimes have extra precision; strip if needed.
    return datetime.fromisoformat(s).astimezone(timezone.utc)


# ---------- error ----------

class NvdError(Exception):
    """NVD API failure that should abort the current run."""


# ---------- client ----------

class NvdClient:
    """Synchronous httpx client for NVD."""

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 30.0,
        user_agent: str = "ccc/0.1 (+https://github.com/zynsec/ccc)",
    ) -> None:
        headers = {"User-Agent": user_agent, "Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key
        self._client = httpx.Client(timeout=timeout, headers=headers)
        self._last_request_ts: float = 0.0

    def __enter__(self) -> "NvdClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _pace(self) -> None:
        delta = time.monotonic() - self._last_request_ts
        if delta < REQUEST_PACING:
            time.sleep(REQUEST_PACING - delta)

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        """One GET with rate-limit pacing + 429 Retry-After honoring."""
        for attempt in range(3):
            self._pace()
            try:
                self._last_request_ts = time.monotonic()
                resp = self._client.get(NVD_URL, params=params)
            except httpx.HTTPError as e:
                if attempt == 2:
                    raise NvdError(f"NVD request failed: {e}") from e
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as e:
                    raise NvdError(f"NVD returned non-JSON: {e}") from e

            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "30"))
                time.sleep(min(retry_after, 120))
                continue

            if resp.status_code in (500, 502, 503, 504):
                if attempt == 2:
                    raise NvdError(f"NVD {resp.status_code}: {resp.text[:200]}")
                time.sleep(2 ** attempt)
                continue

            # 4xx other than 429 - config error, no retry
            raise NvdError(
                f"NVD HTTP {resp.status_code}: {resp.text[:300]}"
            )
        raise NvdError("NVD: retries exhausted")

    def fetch_window(
        self,
        start: datetime,
        end: datetime,
    ) -> Iterator[NvdCve]:
        """Yield every CVE modified in [start, end). Handles pagination + 120d cap."""
        # Split into <=120d chunks defensively (we already cap at 24h, but be safe).
        chunk_start = start
        while chunk_start < end:
            chunk_end = min(chunk_start + MAX_WINDOW, end)
            yield from self._fetch_chunk(chunk_start, chunk_end)
            chunk_start = chunk_end

    def _fetch_chunk(self, start: datetime, end: datetime) -> Iterator[NvdCve]:
        start_index = 0
        while True:
            params = {
                "lastModStartDate": _fmt(start),
                "lastModEndDate": _fmt(end),
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            data = self._get(params)
            vulnerabilities = data.get("vulnerabilities") or []
            total = int(data.get("totalResults", 0))

            for entry in vulnerabilities:
                cve_obj = entry.get("cve")
                if not cve_obj:
                    continue
                normalized = _normalize(cve_obj)
                if normalized is not None:
                    yield normalized

            # Advance per NVD's own protocol fields, not by len(vulnerabilities).
            # Stops desync if NVD's internal ordering shifts mid-pagination.
            page_size = int(data.get("resultsPerPage", len(vulnerabilities)))
            start_index = int(data.get("startIndex", start_index)) + page_size

            # Empty page mid-stream is NOT terminal: NVD claims more results
            # but returned none. Treat as transient and abort the run so the
            # window is retried (last_run not advanced upstream).
            if not vulnerabilities and start_index < total:
                raise NvdError(
                    f"NVD returned empty page at startIndex={start_index} "
                    f"but totalResults={total}; treating as transient"
                )

            if start_index >= total or not vulnerabilities:
                break


# ---------- normalization ----------

def _normalize(cve: dict[str, Any]) -> NvdCve | None:
    """Convert NVD's nested JSON into our flat NvdCve. Drop rejected CVEs."""
    cve_id = cve.get("id")
    if not cve_id:
        return None

    status = (cve.get("vulnStatus") or "").strip() or "Unknown"
    if status.lower() == "rejected":
        return None

    try:
        published = _parse_dt(cve["published"])
        last_mod = _parse_dt(cve["lastModified"])
    except (KeyError, ValueError):
        return None

    description = _pick_english(cve.get("descriptions") or [])

    cvss_score, cvss_severity, cvss_vector = _pick_cvss(cve.get("metrics") or {})

    cpes = list(_extract_cpes(cve.get("configurations") or []))

    refs = [r["url"] for r in (cve.get("references") or []) if r.get("url")]

    cwes = _extract_cwes(cve.get("weaknesses") or [])

    return NvdCve(
        cve_id=cve_id,
        published=published,
        last_modified=last_mod,
        vuln_status=status,
        description=description,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cvss_vector=cvss_vector,
        cpes=cpes,
        references=refs[:10],  # cap refs to keep cards tidy
        cwes=cwes,
    )


def _extract_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    """Pull CWE IDs from NVD weaknesses[]. Drops NVD-CWE-noinfo/Other sentinels."""
    out: list[str] = []
    for w in weaknesses:
        for d in w.get("description") or []:
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-") and val not in ("CWE-noinfo", "CWE-Other"):
                if val not in out:
                    out.append(val)
    return out


def _pick_english(descs: list[dict[str, Any]]) -> str:
    for d in descs:
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    if descs:
        return (descs[0].get("value") or "").strip()
    return ""


def _pick_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Prefer v3.1, then v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or _severity_from_score(score)
            vec = data.get("vectorString")
            if score is not None:
                return (float(score), sev, vec)
    entries = metrics.get("cvssMetricV2") or []
    for entry in entries:
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if score is not None:
            sev = entry.get("baseSeverity") or _severity_from_score(score)
            return (float(score), sev, data.get("vectorString"))
    return (None, None, None)


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _extract_cpes(configurations: list[dict[str, Any]]) -> Iterator[CpeMatch]:
    """Walk configurations.nodes[].cpeMatch[] yielding vulnerable=true CPEs."""
    for cfg in configurations:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                cpe = cm.get("criteria")
                if not cpe:
                    continue
                yield CpeMatch(cpe=cpe, vulnerable=bool(cm.get("vulnerable")))
