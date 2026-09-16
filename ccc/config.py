# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
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
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

Severity = Literal["critical", "high", "medium", "low"]
AlertMode = Literal["individual", "batch"]
BatchPeriod = Literal["daily", "weekly"]
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
        description="individual = one alert per CVE. batch = one digest per product per period.",
    )
    category: str = Field(
        default="default",
        description="Name of the category this product belongs to (products.yaml).",
    )
    batch_period: BatchPeriod = Field(
        default="daily",
        description="Digest cadence for batch-mode products (daily | weekly).",
    )
    accent_color: str | None = Field(
        default=None,
        description="Hex footer color for cards (inherited from category).",
    )
    category_label: str | None = Field(
        default=None,
        description=(
            "Display name for the card footer (from the category's `label`); "
            "falls back to the category name. None = untiered."
        ),
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
RawProductEntry = str | dict[str, Any]


class Category(BaseModel):
    """One alerting category (tier) from products.yaml.

    Categories group products that share an alert policy:
      - alert_mode: individual = one card per CVE, sent immediately.
      - alert_mode: batch     = one digest per product, flushed every
        batch_period (daily | weekly) instead of every run.
      - accent_color: hex footer line on every card in this category.

    A product entry may override `alert_mode` individually; `batch_period`
    and `accent_color` always come from the category.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, description="Category label (tier name)")
    label: str | None = Field(
        default=None,
        description=(
            "Display name for the card footer, e.g. 'Tier 1 - Production "
            "Stack'. Falls back to `name` when omitted."
        ),
    )
    alert_mode: AlertMode = "individual"
    batch_period: BatchPeriod = "daily"
    accent_color: str | None = Field(
        default=None,
        description="Hex color for the card footer line, e.g. #cc0000. None = no footer.",
    )

    @field_validator("accent_color")
    @classmethod
    def _validate_accent(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", v):
            raise ValueError(
                f"accent_color must be #rrggbb hex, got {v!r}"
            )
        return v


class Config(BaseModel):
    """Top-level config (config.yaml)."""

    # Misspelled keys (severity_flor, kev_bypas_floor, alert_on_updates) MUST
    # fail validation instead of silently defaulting. Oracle audit H1.
    model_config = ConfigDict(extra="forbid")

    nvd_api_key: str | None = Field(
        default=None,
        description="NVD API key. Without it: 5 req/30s. With: 50 req/30s.",
    )
    min_cve_year: int | None = Field(
        default=None,
        ge=1999,
        le=2100,
        description=(
            "Ignore CVEs published before this year. None = no limit. "
            "NVD re-touches old CVEs (lastModified moves), so without this "
            "ancient CVEs keep re-entering the poll window and re-alerting."
        ),
    )
    severity_floor: Severity = "high"
    unauthenticated_only: bool = Field(
        default=False,
        description=(
            "Opt-in: only alert CVEs exploitable without authentication "
            "(CVSS PR:N for v3/v4, Au:N for v2). Off by default."
        ),
    )
    unauthenticated_include_unknown: bool = Field(
        default=True,
        description=(
            "When unauthenticated_only is on: CVEs with no parseable CVSS "
            "vector (e.g. NVD 'Awaiting Analysis') still alert. Set false to "
            "require a confirmed unauthenticated vector."
        ),
    )
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


DEFAULT_CATEGORY = "default"


def load_categories_and_products(
    path: Path,
) -> tuple[dict[str, Category], list[RawProductEntry]]:
    """Load + validate products.yaml, returning (categories, raw_entries).

    Categories are OPTIONAL. When absent, an implicit `default` category
    (alert_mode=individual, batch_period=daily) is used for every product.

    Every dict entry may reference a category by name; unknown names are a
    validation error. Plain-string entries always belong to `default`.
    """
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("products.yaml root must be a mapping")

    # --- categories (optional) ---
    raw_categories = data.get("categories") or {}
    if not isinstance(raw_categories, dict):
        raise ValueError("'categories' must be a mapping of name -> policy")
    categories: dict[str, Category] = {}
    for name, policy in raw_categories.items():
        if not isinstance(policy, dict):
            raise ValueError(
                f"categories[{name!r}]: must be a mapping with alert_mode"
            )
        try:
            categories[name] = Category(name=name, **policy)
        except Exception as e:
            raise ValueError(f"categories[{name!r}]: {e}") from e
    if DEFAULT_CATEGORY not in categories:
        categories[DEFAULT_CATEGORY] = Category(name=DEFAULT_CATEGORY)

    # --- products ---
    raw_list = data.get("products")
    if not isinstance(raw_list, list) or not raw_list:
        raise ValueError("products.yaml must have a non-empty 'products' list")

    allowed_keys = {"name", "cpe", "alert_mode", "category"}
    for i, entry in enumerate(raw_list):
        if isinstance(entry, str):
            if not entry.strip():
                raise ValueError(f"products[{i}]: empty string")
        elif isinstance(entry, dict):
            if "name" not in entry or "cpe" not in entry:
                raise ValueError(
                    f"products[{i}]: dict entry must have both 'name' and 'cpe' keys"
                )
            extra = set(entry.keys()) - allowed_keys
            if extra:
                raise ValueError(f"products[{i}]: unknown key(s) {sorted(extra)}")
            am = entry.get("alert_mode", "individual")
            if am not in {"individual", "batch"}:
                raise ValueError(
                    f"products[{i}]: alert_mode must be 'individual' or 'batch', got {am!r}"
                )
            cat = entry.get("category", DEFAULT_CATEGORY)
            if cat not in categories:
                raise ValueError(
                    f"products[{i}]: unknown category {cat!r}. "
                    f"Known categories: {sorted(categories)}"
                )
        else:
            raise ValueError(
                f"products[{i}]: must be a string (name) or dict (name+cpe), "
                f"got {type(entry).__name__}"
            )
    return categories, raw_list


def build_product(
    name: str,
    cpe: str,
    alert_mode: AlertMode = "individual",
    category: str = DEFAULT_CATEGORY,
    batch_period: BatchPeriod = "daily",
    accent_color: str | None = None,
    category_label: str | None = None,
) -> Product:
    """Construct a validated Product from a resolved name+cpe pair."""
    return Product(
        name=name,
        cpe=cpe,
        alert_mode=alert_mode,
        category=category,
        batch_period=batch_period,
        accent_color=accent_color,
        category_label=category_label,
    )


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
