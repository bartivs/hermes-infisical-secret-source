from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ErrorKind(StrEnum):
    NOT_CONFIGURED = "not_configured"
    BINARY_MISSING = "binary_missing"
    AUTH_FAILED = "auth_failed"
    AUTH_EXPIRED = "auth_expired"
    REF_INVALID = "ref_invalid"
    NETWORK = "network"
    EMPTY_VALUE = "empty_value"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


@dataclass
class FetchResult:
    secrets: dict[str, str] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: ErrorKind | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def fail(self, error: str, kind: ErrorKind) -> FetchResult:
        self.error = error
        self.error_kind = kind
        return self


class SecretSource:
    api_version = 1
    name = ""
    label = ""
    shape = "mapped"
    scheme = None
    token_env_key = None
    default_token_env = ""
    override_existing_default = False

    def is_enabled(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("enabled"))

    def token_env(self, cfg: dict) -> str:
        if isinstance(cfg, dict) and self.token_env_key:
            return str(cfg.get(self.token_env_key) or self.default_token_env)
        return self.default_token_env

    def protected_env_vars(self, cfg: dict) -> frozenset[str]:
        return frozenset({self.token_env(cfg)}) if self.token_env_key else frozenset()

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        try:
            value = float((cfg or {}).get("timeout_seconds", 120))
        except (TypeError, ValueError):
            value = 120
        return value if value > 0 else 120


def classify_cli_error(message: str, rules: Sequence[tuple[ErrorKind, Sequence[str]]]) -> ErrorKind:
    lowered = message.lower()
    for kind, tokens in rules:
        if any(token in lowered for token in tokens):
            return kind
    return ErrorKind.INTERNAL


def is_valid_env_name(name: str) -> bool:
    return bool(name) and name.replace("_", "").isalnum() and not name[0].isdigit()


def run_secret_cli(*args: Any, **kwargs: Any):
    raise RuntimeError("stub helper")
