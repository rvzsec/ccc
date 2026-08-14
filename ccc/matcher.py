# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Match NVD CVEs against the user's product list and apply the alert gate.

Match rule:
  A CVE matches a Product if any of its `vulnerable=true` cpeMatch entries
  shares the same (part, vendor, product) triple as the Product's CPE.

  Wildcards: `cpe:2.3:a:apache:log4j:*` matches any Apache Log4j version.
  Strict version pin: `cpe:2.3:a:apache:log4j:2.14.1:*:...` matches only that
  version (we compare the full string when the user's CPE has no `*` in the
  version slot).

Alert gate:
  Alert IFF
    matched   AND
    not vuln_status == 'Rejected'   (already filtered in nvd.py, double check)
    AND ( cvss_score >= floor  OR  kev_bypass_floor AND kev_listed )
"""
from __future__ import annotations

from dataclasses import dataclass

from ccc.config import Config, Product, SEVERITY_SCORES
from ccc.nvd import NvdCve


@dataclass
class Match:
    """A CVE that matched at least one product and passed the alert gate."""

    cve: NvdCve
    products: list[Product]
    epss: float | None
    kev: bool
    kev_name: str = ""   # CISA-curated title for KEV CVEs, empty otherwise

    @property
    def severity_label(self) -> str:
        return (self.cve.cvss_severity or "UNKNOWN").upper()

    @property
    def is_kev_bypass(self) -> bool:
        """True if KEV alone (not CVSS) is what got this past the floor."""
        return self.kev and (
            self.cve.cvss_score is None
            or self.cve.cvss_score < SEVERITY_SCORES["high"]
        )


def _parse_triple(cpe: str) -> tuple[str, str, str] | None:
    # NVD historically returns mixed-case CPEs ("a" vs "A", "Apache" vs "apache").
    # Lowercase ALL three slots so the triple compares deterministically.
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    return (parts[2].lower(), parts[3].lower(), parts[4].lower())


def _version_slot(cpe: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return parts[5]


def match_cve(cve: NvdCve, products: list[Product]) -> list[Product]:
    """Return list of Products this CVE matches. Empty list = no match."""
    hits: list[Product] = []
    cve_triples: set[tuple[str, str, str]] = set()
    for cm in cve.cpes:
        if not cm.vulnerable:
            continue
        triple = _parse_triple(cm.cpe)
        if triple is not None:
            cve_triples.add(triple)

    if not cve_triples:
        return []

    for product in products:
        prod_triple = product.cpe_triple()
        if prod_triple not in cve_triples:
            continue

        # If user pinned a specific version, require an exact CPE match.
        # Lowercase both sides since NVD returns mixed-case CPEs sometimes.
        prod_version = _version_slot(product.cpe)
        if prod_version and prod_version != "*":
            target_prefix = ":".join(product.cpe.lower().split(":")[:6]) + ":"
            if not any(
                cm.cpe.lower().startswith(target_prefix)
                for cm in cve.cpes if cm.vulnerable
            ):
                continue

        hits.append(product)

    return hits


def passes_gate(
    cve: NvdCve,
    cfg: Config,
    kev_listed: bool,
) -> bool:
    """Apply the severity floor + KEV bypass."""
    if cve.vuln_status.lower() == "rejected":
        return False

    floor = cfg.severity_floor_score()

    if cfg.kev_bypass_floor and kev_listed:
        return True

    if cve.cvss_score is None:
        # No score yet. Only alert if KEV (handled above). Otherwise silence.
        return False

    return cve.cvss_score >= floor


def find_matches(
    cves: list[NvdCve],
    products: list[Product],
    cfg: Config,
    kev_map: dict[str, str],
    epss_map: dict[str, float],
) -> list[Match]:
    """Run match + gate over a batch of CVEs.

    kev_map: {cve_id: vulnerabilityName} from CISA KEV. Membership check uses
    `cve.cve_id in kev_map`; the value (when present) is the CISA-curated title.
    """
    out: list[Match] = []
    min_year = cfg.min_cve_year
    for cve in cves:
        # Operator cut-off: never alert on CVEs published before this year.
        # NVD re-touches ancient CVEs (lastModified moves) which would
        # otherwise keep them entering the poll window forever.
        if min_year is not None and cve.published.year < min_year:
            continue
        product_hits = match_cve(cve, products)
        if not product_hits:
            continue
        kev = cve.cve_id in kev_map
        if not passes_gate(cve, cfg, kev):
            continue
        out.append(
            Match(
                cve=cve,
                products=product_hits,
                epss=epss_map.get(cve.cve_id),
                kev=kev,
                kev_name=kev_map.get(cve.cve_id, ""),
            )
        )
    return out
