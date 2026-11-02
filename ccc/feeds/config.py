# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Feed config loading & validation (feeds.yaml).

feeds.yaml is OPTIONAL. When absent, C³ behaves exactly as today (NVD only).

Each feed entry is declarative:

  feeds:
    - name: "GitLab Releases"
      url: "https://docs.gitlab.com/releases/all-releases.xml"
      format: atom                      # atom | rss
      match:                            # omit -> alert on every new entry
        any:
          - { field: title,   contains: ["Security", "Critical Patch"] }
          - { field: content, regex: 'CVE-\\d{4}-\\d+' }
      extract:                          # optional named regex captures
        cves: { from: content, regex: 'CVE-\\d{4}-\\d+' }
      enrich: true                      # look extracted CVEs up in NVD/KEV/EPSS
      category: tier1                   # reuses products.yaml categories
      alert_mode: individual

Categories are shared with products.yaml: the caller resolves the category map
once and hands it to load_feeds so accent colours / labels are a single source
of truth.

Loaded with yaml.safe_load (NEVER yaml.load - RCE risk).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from ccc.config import DEFAULT_CATEGORY, AlertMode, BatchPeriod, Category

FeedFormat = Literal["atom", "rss"]

# Fields exposed to match: / extract: for the atom/rss presets.
FEED_FIELDS = frozenset(
    {"title", "link", "id", "published", "updated", "summary", "content", "author", "category"}
)


class MatchCondition(BaseModel):
    """One predicate against a single feed-entry field.

    Exactly one operator (contains | regex | equals) must be set.
      contains : case-insensitive OR over the given terms (substring).
      regex    : Python re.search against the field value.
      equals   : exact string match.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    contains: list[str] | None = None
    regex: str | None = None
    equals: str | None = None

    @field_validator("field")
    @classmethod
    def _known_field(cls, v: str) -> str:
        if v not in FEED_FIELDS:
            raise ValueError(
                f"unknown field {v!r}. Known fields: {sorted(FEED_FIELDS)}"
            )
        return v

    @field_validator("contains", mode="before")
    @classmethod
    def _coerce_contains(cls, v: Any) -> Any:
        # Allow a bare string as shorthand for a one-element list.
        if isinstance(v, str):
            return [v]
        return v

    @field_validator("regex")
    @classmethod
    def _valid_regex(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid regex {v!r}: {e}") from e
        return v

    @model_validator(mode="after")
    def _exactly_one_operator(self) -> "MatchCondition":
        set_ops = [
            name
            for name, val in (
                ("contains", self.contains),
                ("regex", self.regex),
                ("equals", self.equals),
            )
            if val is not None
        ]
        if len(set_ops) != 1:
            raise ValueError(
                "each match condition needs exactly one of "
                f"contains|regex|equals, got {set_ops or 'none'}"
            )
        if self.contains is not None and not self.contains:
            raise ValueError("'contains' must have at least one term")
        return self


class MatchRule(BaseModel):
    """A predicate tree. `all` AND `any` both apply when both are present."""

    model_config = ConfigDict(extra="forbid")

    any: list[MatchCondition] | None = None
    all: list[MatchCondition] | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> "MatchRule":
        if not self.any and not self.all:
            raise ValueError("match: needs a non-empty 'any' or 'all' list")
        return self


class ExtractRule(BaseModel):
    """Pull named captures out of a field with a regex (all matches)."""

    model_config = ConfigDict(extra="forbid")

    from_: str = Field(alias="from")
    regex: str

    @field_validator("from_")
    @classmethod
    def _known_field(cls, v: str) -> str:
        if v not in FEED_FIELDS:
            raise ValueError(
                f"extract 'from' {v!r} unknown. Known fields: {sorted(FEED_FIELDS)}"
            )
        return v

    @field_validator("regex")
    @classmethod
    def _valid_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid extract regex {v!r}: {e}") from e
        return v


class FeedSource(BaseModel):
    """One fully-resolved feed to watch (category attrs already inlined)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    url: HttpUrl
    format: FeedFormat
    match: MatchRule | None = None
    extract: dict[str, ExtractRule] = Field(default_factory=dict)
    enrich: bool = False
    alert_mode: AlertMode = "individual"
    category: str = DEFAULT_CATEGORY
    # Inlined from the category (same pattern as config.Product):
    batch_period: BatchPeriod = "daily"
    accent_color: str | None = None
    category_label: str | None = None


def load_feeds(path: Path, categories: dict[str, Category]) -> list[FeedSource]:
    """Load + validate feeds.yaml against a known category map.

    Raises FileNotFoundError if the file is absent (caller decides whether that
    is fatal - normally it just means "no feeds configured"). Any structural or
    value error raises ValueError with a path-qualified message.
    """
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("feeds.yaml root must be a mapping with a 'feeds' key")

    raw_list = data.get("feeds")
    if not isinstance(raw_list, list) or not raw_list:
        raise ValueError("feeds.yaml must have a non-empty 'feeds' list")

    seen_names: set[str] = set()
    out: list[FeedSource] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise ValueError(f"feeds[{i}]: must be a mapping, got {type(entry).__name__}")

        cat_name = entry.get("category", DEFAULT_CATEGORY)
        if cat_name not in categories:
            raise ValueError(
                f"feeds[{i}]: unknown category {cat_name!r}. "
                f"Known categories: {sorted(categories)}"
            )
        cat = categories[cat_name]

        # alert_mode: per-feed override wins over the category default.
        payload = dict(entry)
        payload.setdefault("alert_mode", cat.alert_mode)
        payload["batch_period"] = cat.batch_period
        payload["accent_color"] = cat.accent_color
        payload["category_label"] = cat.label or (
            None if cat_name == DEFAULT_CATEGORY else cat_name
        )

        try:
            feed = FeedSource(**payload)
        except Exception as e:  # pydantic ValidationError et al.
            raise ValueError(f"feeds[{i}] ({entry.get('name', '?')!r}): {e}") from e

        if feed.name in seen_names:
            raise ValueError(f"feeds[{i}]: duplicate feed name {feed.name!r}")
        seen_names.add(feed.name)
        out.append(feed)

    return out
