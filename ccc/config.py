"""Config loading & validation.

Two files:
- config.yaml    : runtime config (NVD key, severity floor, webhook, paths)
- products.yaml  : list of products to monitor

products.yaml accepts either:
  - "jenkins"                                  # plain name, CPE auto-resolved
  - {name: "Jenkins", cpe: "cpe:2.3:a:..."}    # explicit override (escape hatch)

Plain-name entries are resolved to CPEs at startup via NVD's CPE API and
cached locally. Operator never needs to know CPE syntax unless auto-resolution
gets a name wrong.

Both files loaded with yaml.safe_load (NEVER yaml.load - RCE risk).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

Severity = Literal["critical", "high", "medium", "low"]
AlertMode = Literal["individual", "batch"]
SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}

# CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
# We require at least part + vendor + product. Rest can be wildcards.
CPE_RE = re.compile(
    r"^cpe:2\.3:[aoh]:[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-]+(:[^:\s]*){0,8}$"
)


class Product(BaseModel):
    """One fully-resolved product to monitor (CPE already known)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, description="Human-readable label")
    cpe: str = Field(..., description="CPE 2.3 string, e.g. cpe:2.3:a:apache:log4j:*")
    alert_mode: AlertMode = Field(
        default="individual",
        description="individual = one alert per CVE. batch = one digest per product per run.",
    )

    @field_validator("cpe")
    @classmethod
    def _validate_cpe(cls, v: str) -> str:
        if not CPE_RE.match(v):
            raise ValueError(
                f"invalid CPE 2.3 string: {v!r}. "
                "Format: cpe:2.3:<a|o|h>:vendor:product[:version:...]"
            )
        return v

    def cpe_triple(self) -> tuple[str, str, str]:
        """Return (part, vendor, product) - the match key. All slots lowercased
        so triples compare deterministically against NVD's mixed-case CPEs."""
        parts = self.cpe.split(":")
        # parts[0]='cpe', parts[1]='2.3', parts[2]=part, parts[3]=vendor, parts[4]=product
        return (parts[2].lower(), parts[3].lower(), parts[4].lower())


# Raw products.yaml entry: either a string (auto-resolve) or a dict (explicit).
RawProductEntry = str | dict


class Config(BaseModel):
    """Top-level config (config.yaml)."""

    # Misspelled keys (severity_flor, kev_bypas_floor, alert_on_updates) MUST
    # fail validation instead of silently defaulting. Oracle audit H1.
    model_config = ConfigDict(extra="forbid")

    nvd_api_key: str | None = Field(
        default=None,
        description="NVD API key. Without it: 5 req/30s. With: 50 req/30s.",
    )
    severity_floor: Severity = "high"
    poll_overlap_minutes: int = Field(default=10, ge=0, le=120)
    max_lookback_hours: int = Field(default=24, ge=1, le=2880)  # 120d NVD cap
    google_chat_webhook: HttpUrl
    kev_bypass_floor: bool = True
    epss_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    # If true, re-alert when an already-seen CVE's hash changes (CVSS bumped,
    # KEV added, vulnStatus moved, etc.). Most teams don't act on these, so
    # the default is false. Set to true if you want the noise.
    alert_on_update: bool = False
    state_dir: Path = Field(default=Path.home() / ".local/state/ccc")
    products_file: Path = Field(default=Path.home() / ".config/ccc/products.yaml")

    @field_validator("state_dir", "products_file")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    def severity_floor_score(self) -> float:
        return SEVERITY_SCORES[self.severity_floor]


def load_config(path: Path) -> Config:
    """Load + validate config.yaml."""
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Config.model_validate(data)


def load_raw_products(path: Path) -> list[RawProductEntry]:
    """Load products.yaml as raw entries (strings OR dicts).

    String entries get auto-resolved to CPEs at startup via resolver.py.
    Dict entries are passed through (operator-provided CPE override).
    Dict entries may optionally include 'alert_mode' (individual|batch).
    """
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("products.yaml root must be a mapping with a 'products' key")
    raw_list = data.get("products")
    if not isinstance(raw_list, list) or not raw_list:
        raise ValueError("products.yaml must have a non-empty 'products' list")
    # Validate shape but don't construct Product yet (CPE may be missing).
    for i, entry in enumerate(raw_list):
        if isinstance(entry, str):
            if not entry.strip():
                raise ValueError(f"products[{i}]: empty string")
        elif isinstance(entry, dict):
            if "name" not in entry or "cpe" not in entry:
                raise ValueError(
                    f"products[{i}]: dict entry must have both 'name' and 'cpe' keys"
                )
            extra = set(entry.keys()) - {"name", "cpe", "alert_mode"}
            if extra:
                raise ValueError(
                    f"products[{i}]: unknown key(s) {sorted(extra)}"
                )
            am = entry.get("alert_mode", "individual")
            if am not in {"individual", "batch"}:
                raise ValueError(
                    f"products[{i}]: alert_mode must be 'individual' or 'batch', got {am!r}"
                )
        else:
            raise ValueError(
                f"products[{i}]: must be a string (name) or dict (name+cpe), "
                f"got {type(entry).__name__}"
            )
    return raw_list


def build_product(name: str, cpe: str, alert_mode: AlertMode = "individual") -> Product:
    """Construct a validated Product from a resolved name+cpe pair."""
    return Product(name=name, cpe=cpe, alert_mode=alert_mode)


# Kept for back-compat with tests that pre-date the resolver. Treats every
# entry as already having a CPE (dict form).
def load_products(path: Path) -> list[Product]:
    raw = load_raw_products(path)
    out: list[Product] = []
    for entry in raw:
        if isinstance(entry, str):
            raise ValueError(
                f"plain-name entry {entry!r} requires CPE resolution; "
                "use the cli path (which calls the resolver) or supply "
                "a full {name, cpe} dict in products.yaml"
            )
        out.append(Product(
            name=entry["name"],
            cpe=entry["cpe"],
            alert_mode=entry.get("alert_mode", "individual"),
        ))
    return out
