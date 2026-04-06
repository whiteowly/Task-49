import importlib
import json
import os


def build_client(tmp_path):
    os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_api.db")
    os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_api.key")
    os.environ["METROOPS_RUNTIME_ENV"] = "test"
    os.environ["DISABLE_TLS_ENFORCEMENT"] = "1"
    module = importlib.import_module("app.app")
    module = importlib.reload(module)
    app = module.create_app()
    app.testing = True
    app.config["DISABLE_TLS_ENFORCEMENT"] = True
    app.init_db()
    return app.test_client(), app


def login_agent(client):
    response = client.post(
        "/login",
        data={"username": "agent01", "password": "MetroOpsPass!01"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def login_admin(client):
    response = client.post(
        "/login",
        data={"username": "admin01", "password": "MetroOpsPass!04"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def authed_post(client, url, **kwargs):
    with client.session_transaction() as sess:
        token = sess.get("csrf_token")
    headers = dict(kwargs.pop("headers", {}) or {})
    if token:
        headers["X-CSRF-Token"] = token
    return client.post(url, headers=headers, **kwargs)


def test_admin_bootstrap_governance_endpoints_and_audit(tmp_path):
    client, app = build_client(tmp_path)
    login_admin(client)

    org = authed_post(client, "/admin/organizations", json={"name": "North Org"})
    assert org.status_code == 201
    org_id = org.get_json()["organization_id"]

    provision = authed_post(
        client,
        f"/admin/organizations/{org_id}/users",
        json={
            "username": "org_user_1",
            "password": "LongEnoughPass!99",
            "role": "employee",
        },
    )
    assert provision.status_code == 201
    user_id = provision.get_json()["user_id"]

    assign = authed_post(
        client,
        f"/admin/organizations/{org_id}/roles/assign",
        json={"user_id": user_id, "role": "supervisor"},
    )
    assert assign.status_code == 200

    revoke = authed_post(
        client,
        f"/admin/organizations/{org_id}/roles/revoke",
        json={"user_id": user_id},
    )
    assert revoke.status_code == 200

    with app.app_context():
        db = app.get_db()
        org_row = db.execute(
            "SELECT id FROM organizations WHERE id=?", (org_id,)
        ).fetchone()
        assert org_row is not None
        assignment = db.execute(
            "SELECT role,status FROM organization_role_assignments WHERE organization_id=? AND user_id=?",
            (org_id, user_id),
        ).fetchone()
        assert assignment is not None
        assert assignment["role"] == "supervisor"
        assert assignment["status"] == "revoked"
        audit_count = db.execute(
            "SELECT COUNT(*) FROM admin_audit_log WHERE organization_id=? AND target_user_id=?",
            (org_id, user_id),
        ).fetchone()[0]
        assert audit_count >= 3


def test_admin_bootstrap_non_admin_forbidden(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    org = authed_post(client, "/admin/organizations", json={"name": "Blocked Org"})
    assert org.status_code == 403

    provision = authed_post(
        client,
        "/admin/organizations/1/users",
        json={
            "username": "blocked_user",
            "password": "LongEnoughPass!22",
            "role": "employee",
        },
    )
    assert provision.status_code == 403

    assign = authed_post(
        client,
        "/admin/organizations/1/roles/assign",
        json={"user_id": 1, "role": "employee"},
    )
    assert assign.status_code == 403


def test_admin_role_assignment_blocks_cross_organization_target(tmp_path):
    client, _app = build_client(tmp_path)
    login_admin(client)

    org_a = authed_post(client, "/admin/organizations", json={"name": "Org A"})
    org_b = authed_post(client, "/admin/organizations", json={"name": "Org B"})
    assert org_a.status_code == 201
    assert org_b.status_code == 201
    org_a_id = org_a.get_json()["organization_id"]
    org_b_id = org_b.get_json()["organization_id"]

    provision = authed_post(
        client,
        f"/admin/organizations/{org_a_id}/users",
        json={
            "username": "cross_org_user",
            "password": "LongEnoughPass!33",
            "role": "employee",
        },
    )
    assert provision.status_code == 201
    user_id = provision.get_json()["user_id"]

    denied = authed_post(
        client,
        f"/admin/organizations/{org_b_id}/roles/assign",
        json={"user_id": user_id, "role": "supervisor"},
    )
    assert denied.status_code == 422


def test_admin_audit_recursive_redaction_for_nested_payloads(tmp_path):
    client, app = build_client(tmp_path)
    login_admin(client)

    org = authed_post(client, "/admin/organizations", json={"name": "Redaction Org"})
    assert org.status_code == 201
    org_id = org.get_json()["organization_id"]

    provision = authed_post(
        client,
        f"/admin/organizations/{org_id}/users",
        json={
            "username": "redact_user",
            "password": "LongEnoughPass!44",
            "role": "employee",
        },
    )
    assert provision.status_code == 201
    user_id = provision.get_json()["user_id"]

    assign = authed_post(
        client,
        f"/admin/organizations/{org_id}/roles/assign",
        json={
            "user_id": user_id,
            "role": "hr",
            "metadata": {
                "safe": "keep",
                "layer": [{"credentials": {"token": "tok-1", "safe_nested": "ok"}}],
            },
            "before_data": [{"password": "old-secret"}],
            "after_data": {"nested": [{"secret": "new-secret", "note": "kept"}]},
        },
    )
    assert assign.status_code == 200

    with app.app_context():
        db = app.get_db()
        row = db.execute(
            "SELECT metadata,before_data,after_data FROM admin_audit_log WHERE action='role_assigned' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        metadata = json.loads(row["metadata"])
        before_data = json.loads(row["before_data"])
        after_data = json.loads(row["after_data"])

    assert metadata["metadata"]["safe"] == "keep"
    assert metadata["metadata"]["layer"][0]["credentials"] == "***REDACTED***"
    assert before_data["request_before"][0]["password"] == "***REDACTED***"
    assert after_data["request_after"]["nested"][0]["secret"] == "***REDACTED***"
    assert after_data["request_after"]["nested"][0]["note"] == "kept"
