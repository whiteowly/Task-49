import pytest
import sqlite3
import importlib
from datetime import datetime, timezone

UTC = timezone.utc

from app.config import (
    resolve_tls_disable_policy,
    runtime_env_mode,
    validated_gateway_token,
)
from app.db_bootstrap import initialize_database


def test_validated_gateway_token_rejects_placeholder_values():
    token, state = validated_gateway_token("replace-me-for-production")
    assert token == ""
    assert state == "placeholder-like value"


def test_validated_gateway_token_accepts_secure_value():
    token, state = validated_gateway_token("prod-token-abc-123")
    assert token == "prod-token-abc-123"
    assert state == "configured"


def test_runtime_env_mode_defaults_to_production(monkeypatch):
    monkeypatch.delenv("METROOPS_RUNTIME_ENV", raising=False)
    monkeypatch.delenv("FLASK_ENV", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    mode, development_mode = runtime_env_mode()
    assert mode == "production"
    assert development_mode is False


def test_resolve_tls_disable_policy_rejects_production_override(monkeypatch):
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "production")
    with pytest.raises(RuntimeError, match="allowed only in development/test/local"):
        resolve_tls_disable_policy("1")


def test_resolve_tls_disable_policy_allows_development_override(monkeypatch):
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "development")
    runtime_env, tls_disabled = resolve_tls_disable_policy("1")
    assert runtime_env == "development"
    assert tls_disabled is True


def test_non_dev_bootstrap_requires_admin_password(tmp_path, monkeypatch):
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "production")
    monkeypatch.delenv("METROOPS_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    with pytest.raises(
        RuntimeError, match="requires METROOPS_BOOTSTRAP_ADMIN_PASSWORD"
    ):
        initialize_database(
            tmp_path / "prod_bootstrap.db",
            lambda: datetime.now(UTC),
            lambda dt: dt.isoformat(),
        )


def test_non_dev_bootstrap_uses_env_admin_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "production")
    monkeypatch.setenv("METROOPS_BOOTSTRAP_ADMIN_USERNAME", "ops_admin")
    monkeypatch.setenv("METROOPS_BOOTSTRAP_ADMIN_PASSWORD", "ProdBootstrapPass!42")
    db_path = tmp_path / "prod_secure_bootstrap.db"

    initialize_database(db_path, lambda: datetime.now(UTC), lambda dt: dt.isoformat())

    db = sqlite3.connect(db_path)
    rows = db.execute("SELECT username, role FROM users ORDER BY id").fetchall()
    profile = db.execute(
        "SELECT value FROM system_config WHERE key='bootstrap_profile'"
    ).fetchone()[0]
    db.close()

    assert rows == [("ops_admin", "admin")]
    assert profile == "secure_bootstrap_v1"


def test_non_dev_rejects_existing_dev_default_bootstrap_profile(tmp_path, monkeypatch):
    db_path = tmp_path / "dev_seed_then_prod.db"
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "test")
    initialize_database(db_path, lambda: datetime.now(UTC), lambda dt: dt.isoformat())

    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "production")
    monkeypatch.setenv("METROOPS_BOOTSTRAP_ADMIN_PASSWORD", "ProdBootstrapPass!55")
    with pytest.raises(RuntimeError, match="Development default credentials detected"):
        initialize_database(
            db_path, lambda: datetime.now(UTC), lambda dt: dt.isoformat()
        )


def test_non_dev_create_app_requires_explicit_flask_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("METROOPS_DB_PATH", str(tmp_path / "prod_missing_secret.db"))
    monkeypatch.setenv("METROOPS_KEY_PATH", str(tmp_path / "prod_missing_secret.key"))
    monkeypatch.setenv("METROOPS_RUNTIME_ENV", "production")
    monkeypatch.setenv("DISABLE_TLS_ENFORCEMENT", "0")
    monkeypatch.setenv("METROOPS_BOOTSTRAP_ADMIN_PASSWORD", "ProdBootstrapPass!88")
    monkeypatch.delenv("FLASK_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="FLASK_SECRET must be explicitly set"):
        module = importlib.import_module("app.app")
        importlib.reload(module)
