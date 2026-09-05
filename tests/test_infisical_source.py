from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def hermes_import_path(monkeypatch):
    """Use an installed Hermes source tree when tests run on a Hermes host."""
    hermes_root = Path("/usr/local/lib/hermes-agent")
    if hermes_root.exists():
        monkeypatch.syspath_prepend(str(hermes_root))


def source_module():
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "hermes_infisical_plugin", Path(__file__).parents[1] / "__init__.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except ModuleNotFoundError as exc:
        pytest.skip(f"Hermes Agent source tree is required: {exc}")


def test_parse_dotenv_preserves_equals_and_ignores_noise():
    module = source_module()
    assert module.parse_dotenv(
        "# generated\nOPENROUTER_API_KEY=abc=def\nexport EMPTY=\nnot dotenv\n"
    ) == {"OPENROUTER_API_KEY": "abc=def", "EMPTY": ""}


def test_token_file_supports_environment_file(tmp_path):
    module = source_module()
    token_file = tmp_path / "token"
    token_file.write_text("INFISICAL_TOKEN=machine-token\n")
    assert module._read_token_file(str(token_file)) == "machine-token"


def test_disabled_source_and_protected_token():
    module = source_module()
    source = module.InfisicalSource()
    assert source.is_enabled({}) is False
    assert source.protected_env_vars({}) == {"INFISICAL_TOKEN"}


def test_missing_project_is_clean_error(monkeypatch, tmp_path):
    module = source_module()
    source = module.InfisicalSource()
    monkeypatch.setenv("INFISICAL_TOKEN", "test-token")
    result = source.fetch({"enabled": True}, tmp_path)
    assert not result.ok
    assert result.error_kind.value == "not_configured"
    assert result.secrets == {}


def test_fetch_uses_safe_cli_and_returns_secrets(monkeypatch, tmp_path):
    module = source_module()
    source = module.InfisicalSource()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="OPENROUTER_API_KEY=from-infisical\n",
            stderr="",
        )

    monkeypatch.setattr(module, "run_secret_cli", fake_run)
    monkeypatch.setenv("INFISICAL_TOKEN", "test-token")
    result = source.fetch(
        {
            "enabled": True,
            "project_id": "project-123",
            "environment": "prod",
            "domain": "http://infisical.example/api",
        },
        tmp_path,
    )

    assert result.ok
    assert result.secrets == {"OPENROUTER_API_KEY": "from-infisical"}
    assert captured["argv"][:2] == ["infisical", "export"]
    assert "test-token" not in captured["argv"]
    assert captured["kwargs"]["extra_env"]["INFISICAL_TOKEN"] == "test-token"
    assert captured["kwargs"]["extra_env"]["INFISICAL_DOMAIN"] == "http://infisical.example/api"


def test_cli_failure_never_exposes_stderr_or_secret(monkeypatch, tmp_path):
    module = source_module()
    source = module.InfisicalSource()

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="unauthorized: machine token is secret-value",
        )

    monkeypatch.setattr(module, "run_secret_cli", fake_run)
    monkeypatch.setenv("INFISICAL_TOKEN", "secret-value")
    result = source.fetch({"enabled": True, "project_id": "p"}, tmp_path)
    assert not result.ok
    assert result.error_kind.value == "auth_failed"
    assert "secret-value" not in (result.error or "")
