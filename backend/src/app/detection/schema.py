"""Rule file schema (Sigma-inspired, not full Sigma).

Conditions use Sigma-style `field|modifier: value` leaves combined with all/any/not:

    condition:
      all:
        - action|in: [ssh_login, logon]
        - outcome: failure                 # no modifier = equals
        - process_cmdline|re: '(?i)-enc'
        - not:
            tags|contains: system_account

A list value means "any of these". String comparisons are case-insensitive unless the
modifier ends in `_cs`. Four logic types: match, threshold, sequence, first_seen.
"""

import re
from datetime import timedelta
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app import attack

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int) -> timedelta:
    if isinstance(value, int):
        return timedelta(seconds=value)
    m = _DURATION.match(value.strip())
    if not m:
        raise ValueError(f"invalid duration {value!r}; use e.g. 30s, 5m, 1h, 1d")
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2)])


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Attack(Strict):
    tactic: str
    techniques: list[str] = Field(min_length=1)

    @field_validator("tactic")
    @classmethod
    def _tactic(cls, v: str) -> str:
        known = attack.tactic_order()
        if v not in known:
            raise ValueError(
                f"unknown tactic {v!r} (ATT&CK {attack.version()}: {', '.join(known)})"
            )
        return v

    @field_validator("techniques")
    @classmethod
    def _techniques(cls, v: list[str]) -> list[str]:
        for t in v:
            if not TECHNIQUE_ID.match(t):
                raise ValueError(f"malformed technique id {t!r}")
        return v


def _duration_field(v: Any) -> timedelta:
    if isinstance(v, timedelta):
        return v
    if isinstance(v, str | int):
        return parse_duration(v)
    raise ValueError("duration must be a string like '5m'")


class Suppress(Strict):
    """Repeated hits for the same keys within `window` extend one alert instead of
    opening new ones."""

    by: list[str] = Field(default_factory=lambda: ["host", "user", "src_ip"])
    window: timedelta = timedelta(hours=1)

    _w = field_validator("window", mode="before")(_duration_field)


class MatchLogic(Strict):
    type: Literal["match"]
    condition: Any
    suppress: Suppress = Suppress()


class ThresholdLogic(Strict):
    type: Literal["threshold"]
    condition: Any
    group_by: list[str] = Field(min_length=1)
    window: timedelta
    threshold: int = Field(ge=2)
    distinct: str | None = None  # count distinct values of this field instead of events

    _w = field_validator("window", mode="before")(_duration_field)


class SequenceStep(Strict):
    name: str
    condition: Any
    min_count: int = Field(default=1, ge=1)


class SequenceLogic(Strict):
    type: Literal["sequence"]
    by: list[str] = Field(min_length=1)
    within: timedelta
    steps: list[SequenceStep] = Field(min_length=2, max_length=5)

    _w = field_validator("within", mode="before")(_duration_field)


class FirstSeenLogic(Strict):
    type: Literal["first_seen"]
    condition: Any
    entity: str  # e.g. host
    value: str  # e.g. process_name
    # Only alert once the entity has this much history; before that we are learning.
    min_history: timedelta = timedelta(days=1)

    _w = field_validator("min_history", mode="before")(_duration_field)


Logic = Annotated[
    MatchLogic | ThresholdLogic | SequenceLogic | FirstSeenLogic, Field(discriminator="type")
]


class RuleSpec(Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10)
    severity: Literal["low", "medium", "high", "critical"]
    attack: Attack | None = None  # None = no hard mapping (e.g. discovery aids)
    logic: Logic
    false_positives: list[str] = Field(min_length=1)
    references: list[str] = Field(default_factory=list)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _conditions_compile(self) -> "RuleSpec":
        # Imported here to avoid a cycle; compiling validates fields, modifiers, regexes.
        from app.detection.conditions import compile_condition

        logic = self.logic
        if isinstance(logic, SequenceLogic):
            for step in logic.steps:
                compile_condition(step.condition)
        else:
            compile_condition(logic.condition)
        return self
