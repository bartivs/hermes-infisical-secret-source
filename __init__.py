"""Infisical secret-source plugin for Hermes Agent.

The plugin intentionally delegates environment mutation, precedence, and
provenance to Hermes' secret-source orchestrator. It only fetches a dotenv
export from the Infisical CLI.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    classify_cli_error,
    is_valid_env_name,
    run_secret_cli,
)

_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse the Infisical CLI's dotenv output without shell evaluation."""
    secrets: dict[str, str] = {}
    for raw_line in text.replace("\r\n", "\n").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match:
            secrets[match.group(1)] = _unquote(match.group(2))
    return secrets


def _read_token_file(path_value: str) -> str | None:
    """Read either a raw token or an EnvironmentFile-style token file."""
    path = Path(path_value).expanduser()
    text = path.read_text(encoding="utf-8").strip()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("INFISICAL_TOKEN="):
            return _unquote(line.split("=", 1)[1]).strip() or None
    return text or None


class InfisicalSource(SecretSource):
    """Bulk secret source backed by a machine identity and Infisical CLI."""

    name = "infisical"
    label = "Infisical"
    shape = "bulk"
    token_env_key = "token_env"
    default_token_env = "INFISICAL_TOKEN"
    override_existing_default = True
    remediation_hints = {
        ErrorKind.NOT_CONFIGURED: (
            "Set secrets.infisical.project_id and provide the machine identity "
            "token via the configured token_env or token_file."
        ),
        ErrorKind.BINARY_MISSING: (
            "Install the Infisical CLI or set secrets.infisical.cli_path."
        ),
        ErrorKind.AUTH_FAILED: (
            "Verify the Infisical machine identity token and project membership."
        ),
        ErrorKind.AUTH_EXPIRED: (
            "Rotate the Infisical machine identity token and update its secret source."
        ),
        ErrorKind.NETWORK: (
            "Check connectivity to the configured Infisical domain."
        ),
    }

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable Infisical secret loading", "default": False},
            "project_id": {"description": "Infisical project UUID", "default": ""},
            "environment": {"description": "Infisical environment slug", "default": "prod"},
            "secret_path": {"description": "Infisical folder path", "default": "/"},
            "domain": {
                "description": "Infisical API domain, including /api for self-hosted instances",
                "default": "https://app.infisical.com/api",
            },
            "cli_path": {"description": "Infisical CLI executable", "default": "infisical"},
            "token_env": {
                "description": "Environment variable containing the token",
                "default": "INFISICAL_TOKEN",
            },
            "token_file": {
                "description": "Optional root-only raw token or EnvironmentFile",
                "default": "",
            },
            "timeout_seconds": {"description": "Maximum fetch time", "default": 120},
            "cli_timeout_seconds": {"description": "Maximum Infisical CLI time", "default": 30},
        }

    def _token(self, cfg: dict, token_env: str) -> str | None:
        token_file = str(cfg.get("token_file") or "").strip()
        if token_file:
            return _read_token_file(token_file)
        return os.environ.get(token_env, "").strip() or None

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}
        try:
            token_env = self.token_env(cfg)
            if not is_valid_env_name(token_env):
                return result.fail(
                    "token_env must be a valid environment variable name",
                    ErrorKind.REF_INVALID,
                )

            project_id = str(cfg.get("project_id") or "").strip()
            environment = str(cfg.get("environment") or "prod").strip()
            domain = str(cfg.get("domain") or "https://app.infisical.com/api").strip().rstrip("/")
            secret_path = str(cfg.get("secret_path") or "/").strip() or "/"
            cli_path = str(cfg.get("cli_path") or "infisical").strip() or "infisical"
            token = self._token(cfg, token_env)

            if not project_id:
                return result.fail(
                    "Infisical project_id is not configured",
                    ErrorKind.NOT_CONFIGURED,
                )
            if not environment or not domain:
                return result.fail(
                    "Infisical environment and domain are required",
                    ErrorKind.NOT_CONFIGURED,
                )
            if not token:
                return result.fail(
                    "Infisical machine identity token is not configured",
                    ErrorKind.NOT_CONFIGURED,
                )

            try:
                cli_timeout = float(cfg.get("cli_timeout_seconds", 30))
            except (TypeError, ValueError):
                cli_timeout = 30.0
            if cli_timeout <= 0:
                cli_timeout = 30.0

            proc = run_secret_cli(
                [
                    cli_path,
                    "export",
                    f"--env={environment}",
                    f"--projectId={project_id}",
                    f"--path={secret_path}",
                    "--format=dotenv",
                    "--silent",
                ],
                extra_env={
                    token_env: token,
                    "INFISICAL_DOMAIN": domain,
                    "INFISICAL_TELEMETRY": "false",
                },
                timeout=cli_timeout,
            )
            if proc.returncode != 0:
                kind = classify_cli_error(
                    proc.stderr,
                    (
                        (ErrorKind.AUTH_EXPIRED, ("expired", "token has expired")),
                        (
                            ErrorKind.AUTH_FAILED,
                            ("unauthorized", "invalid token", "401", "forbidden"),
                        ),
                        (
                            ErrorKind.NETWORK,
                            ("timeout", "connection", "network", "no such host", "dial tcp"),
                        ),
                    ),
                )
                return result.fail(f"Infisical CLI exited with status {proc.returncode}", kind)

            result.secrets = parse_dotenv(proc.stdout)
            if not result.secrets:
                return result.fail("Infisical returned no dotenv secrets", ErrorKind.EMPTY_VALUE)
            return result
        except FileNotFoundError:
            return result.fail("Infisical token_file does not exist", ErrorKind.NOT_CONFIGURED)
        except PermissionError:
            return result.fail("Infisical token_file is not readable", ErrorKind.NOT_CONFIGURED)
        except RuntimeError as exc:
            message = str(exc).lower()
            kind = ErrorKind.TIMEOUT if "timed out" in message else ErrorKind.BINARY_MISSING
            return result.fail("Infisical CLI could not be executed", kind)
        except Exception:
            # Secret-source contract: never let a plugin failure break Hermes startup.
            return result.fail("Unexpected Infisical secret-source failure", ErrorKind.INTERNAL)


def register(ctx) -> None:
    """Register the source with Hermes' secret-source orchestrator."""
    ctx.register_secret_source(InfisicalSource())


__all__ = ["InfisicalSource", "parse_dotenv", "register"]
