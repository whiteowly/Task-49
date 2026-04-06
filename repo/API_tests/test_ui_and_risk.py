import importlib
import logging
import os
from io import BytesIO
from datetime import datetime, timedelta, timezone

UTC = timezone.utc

import pytest


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


def login_supervisor(client):
    response = client.post(
        "/login",
        data={"username": "supervisor01", "password": "MetroOpsPass!02"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def login_hr(client):
    response = client.post(
        "/login",
        data={"username": "hr01", "password": "MetroOpsPass!03"},
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


def test_arrival_board_scheduled_fallback(tmp_path):
    client, _app = build_client(tmp_path)
    page = client.get("/api/arrival-board")
    assert page.status_code == 200
    assert b"Scheduled" in page.data
    assert b"Last updated at" in page.data


def test_arrival_board_live_mode_with_recent_ping(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)
    now = datetime.now(UTC).isoformat()
    with app.app_context():
        app.get_db().execute(
            "INSERT INTO vehicle_pings (vehicle_id,route_id,stop_sequence,lat,lon,speed_mph,ping_time,source) VALUES (?,?,?,?,?,?,?,?)",
            ("LIVE-1", 1, 1, 0.0, 0.0, 25.0, now, "csv"),
        )
        app.get_db().commit()

    page = client.get("/api/arrival-board")
    assert page.status_code == 200
    assert b"Live" in page.data


def test_arrival_board_threshold_edges(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)
    now = datetime.now(UTC)
    with app.app_context():
        app.get_db().execute(
            "INSERT INTO vehicle_pings (vehicle_id,route_id,stop_sequence,lat,lon,speed_mph,ping_time,source) VALUES (?,?,?,?,?,?,?,?)",
            (
                "EDGE-IN",
                1,
                1,
                0.0,
                0.0,
                20.0,
                (now - timedelta(minutes=2) + timedelta(seconds=1)).isoformat(),
                "csv",
            ),
        )
        app.get_db().execute(
            "INSERT INTO vehicle_pings (vehicle_id,route_id,stop_sequence,lat,lon,speed_mph,ping_time,source) VALUES (?,?,?,?,?,?,?,?)",
            (
                "EDGE-OUT",
                2,
                1,
                0.0,
                0.0,
                20.0,
                (now - timedelta(minutes=2) - timedelta(seconds=1)).isoformat(),
                "csv",
            ),
        )
        app.get_db().commit()

    route1 = client.get("/api/arrival-board?route_id=1")
    assert route1.status_code == 200
    assert b"Live" in route1.data

    route2 = client.get("/api/arrival-board?route_id=2")
    assert route2.status_code == 200
    assert b"Scheduled" in route2.data


def test_excessive_refresh_generates_risk_event(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    for _ in range(30):
        response = client.get("/api/heartbeat?screen=dashboard")
        assert response.status_code == 200
        with app.app_context():
            app.get_db().execute(
                "UPDATE refresh_cadence SET last_seen=? WHERE actor_key=? AND screen=?",
                (
                    (datetime.now(UTC) - timedelta(seconds=11)).isoformat(),
                    "user:1",
                    "heartbeat:dashboard",
                ),
            )
            app.get_db().commit()

    throttled = client.get("/api/heartbeat?screen=dashboard")
    assert throttled.status_code == 429

    with app.app_context():
        count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='excessive_refresh'"
            )
            .fetchone()[0]
        )
        assert count >= 1

    other_screen = client.get("/api/heartbeat?screen=kiosk")
    assert other_screen.status_code == 200


def test_strict_ten_second_refresh_cap(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    first = client.get("/api/heartbeat?screen=dashboard")
    assert first.status_code == 200
    second = client.get("/api/heartbeat?screen=dashboard")
    assert second.status_code == 429


def test_refresh_governance_isolated_by_screen_query(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    first = client.get("/api/heartbeat?screen=alpha")
    assert first.status_code == 200
    second = client.get("/api/heartbeat?screen=beta")
    assert second.status_code == 200


def test_cadence_rejected_heartbeat_attempts_still_trigger_excessive_refresh_risk(
    tmp_path,
):
    client, app = build_client(tmp_path)
    login_agent(client)

    first = client.get("/api/heartbeat?screen=rapid")
    assert first.status_code == 200
    for _ in range(31):
        blocked = client.get("/api/heartbeat?screen=rapid")
        assert blocked.status_code == 429

    with app.app_context():
        count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='excessive_refresh' AND details LIKE 'screen=heartbeat:rapid,%'"
            )
            .fetchone()[0]
        )
        assert count >= 1


def test_refresh_governance_applies_to_arrival_endpoint(tmp_path):
    client, _app = build_client(tmp_path)
    first = client.get("/api/arrival-board")
    assert first.status_code == 200
    second = client.get("/api/arrival-board")
    assert second.status_code == 429


def test_seat_availability_query_endpoint_and_refresh_cap(tmp_path):
    client, app = build_client(tmp_path)
    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )

    first = client.get(
        f"/api/seat-availability?departure_id={dep_id}&screen=dashboard-seat-availability"
    )
    assert first.status_code == 200
    assert b"Seats remaining" in first.data
    second = client.get(
        f"/api/seat-availability?departure_id={dep_id}&screen=dashboard-seat-availability"
    )
    assert second.status_code == 429


def test_dashboard_contains_htmx_seat_refresh(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b'hx-trigger="load, every 10s, change from:#departure-select"' in page.data
    assert b"screen=dashboard-seat-availability" in page.data


def test_dashboard_recommendation_widget_telemetry_hooks_present(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b'id="recommendation-widget"' in page.data
    assert b'data-widget-key="suggested-times"' in page.data
    assert b'id="exp-label"' in page.data

    js = client.get("/static/app.js")
    assert js.status_code == 200
    body = js.get_data(as_text=True)
    assert "/api/analytics/recommendation-event" in body
    assert "rec_impression" in body
    assert "rec_click" in body
    assert 'document.body.addEventListener("htmx:timeout"' in body
    assert "syncPollingState" in body


def test_dashboard_social_actions_ui_and_wiring_present(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b'id="social-actions-panel"' in page.data
    assert b'id="social-target-user-id"' in page.data
    assert b'id="social-relation"' in page.data
    assert b"data-social-action" in page.data
    assert b'id="social-action-status"' in page.data

    js = client.get("/static/app.js")
    assert js.status_code == 200
    body = js.get_data(as_text=True)
    assert "initSocialActionPanel" in body
    assert "/api/social/action" in body
    assert "Submitting social action..." in body


def test_profile_social_actions_ui_state_and_mutual_follow_visibility(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    page_before = client.get("/profiles/2")
    assert page_before.status_code == 200
    assert b'id="profile-social-actions"' in page_before.data
    assert b'id="profile-social-follow"' in page_before.data
    assert b"Follow" in page_before.data
    assert b"Mutual follow required" in page_before.data

    follow = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "follow"}
    )
    assert follow.status_code == 200

    login_supervisor(client)
    follow_back = authed_post(
        client, "/api/social/action", json={"target_user_id": 1, "relation": "follow"}
    )
    assert follow_back.status_code == 200

    login_agent(client)
    page_after = client.get("/profiles/2")
    assert page_after.status_code == 200
    assert b"Unfollow" in page_after.data
    assert b"Mutual follow active" in page_after.data

    js = client.get("/static/app.js")
    assert js.status_code == 200
    body = js.get_data(as_text=True)
    assert "initProfileSocialActions" in body
    assert "Submitting '" in body


def test_profile_social_actions_unauthorized_and_validation_failures(tmp_path):
    client, _app = build_client(tmp_path)

    unauth = client.post(
        "/api/social/action", json={"target_user_id": 2, "relation": "follow"}
    )
    assert unauth.status_code == 302

    login_agent(client)
    invalid_relation = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "INVALID"}
    )
    assert invalid_relation.status_code == 422

    missing_relation = authed_post(
        client, "/api/social/action", json={"target_user_id": 2}
    )
    assert missing_relation.status_code == 422

    missing_target = authed_post(
        client,
        "/api/social/action",
        json={"target_user_id": 999999, "relation": "follow"},
    )
    assert missing_target.status_code == 404


def test_profile_social_duplicate_click_protection_idempotent_follow(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    first = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "follow"}
    )
    second = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "follow"}
    )
    assert first.status_code == 200
    assert second.status_code == 200

    with app.app_context():
        count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM relationships WHERE user_a=1 AND user_b=2 AND relation='follow'"
            )
            .fetchone()[0]
        )
        assert count == 1


def test_offline_banner_contract_server_and_client_paths(tmp_path):
    client, _app = build_client(tmp_path)

    kiosk = client.get("/kiosk")
    assert kiosk.status_code == 200
    assert b'id="offline-banner"' in kiosk.data
    assert b"Offline" in kiosk.data

    js = client.get("/static/app.js")
    assert js.status_code == 200
    body = js.get_data(as_text=True)
    assert "fetch(`/api/heartbeat?screen=${encodeURIComponent(screenName)}`" in body
    assert 'document.body.addEventListener("htmx:responseError"' in body
    assert 'document.body.addEventListener("htmx:sendError"' in body
    assert 'offlineBanner.classList.toggle("hidden", !isOffline);' in body

    heartbeat = client.get("/api/heartbeat?screen=offline-contract")
    assert heartbeat.status_code == 200
    payload = heartbeat.get_json()
    assert payload["ok"] is True
    assert "time" in payload


def test_depot_mutation_requires_permission(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    denied = authed_post(client, "/api/depot/bins/1/freeze", data={"frozen": "1"})
    assert denied.status_code == 403

    login_supervisor(client)
    nonce_for_freeze = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    allowed = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "1", "request_nonce": nonce_for_freeze},
    )
    assert allowed.status_code == 200

    nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    allocate = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": nonce,
            "bin_id": 1,
            "item_name": "Crate",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert allocate.status_code == 409

    freeze_back_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    freeze_back = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "0", "request_nonce": freeze_back_nonce},
    )
    assert freeze_back.status_code == 200
    nonce2 = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    frozen_then_allocate = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": nonce2,
            "bin_id": 1,
            "item_name": "Crate2",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert frozen_then_allocate.status_code == 200

    missing_bin_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    missing_bin = authed_post(
        client,
        "/api/depot/bins/999999/freeze",
        data={"frozen": "1", "request_nonce": missing_bin_nonce},
    )
    assert missing_bin.status_code == 404


def test_privileged_endpoints_deny_employee_role(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    assert client.get("/supervisor/experiments").status_code == 403
    assert client.get("/analyst/metrics").status_code == 403
    assert client.get("/depot/manage").status_code == 403
    assert client.get("/reports").status_code == 403

    denied_admin = authed_post(
        client,
        "/admin/users",
        json={
            "username": "x",
            "password": "LongEnoughPass!123",
            "role": "employee",
            "depot_assignment": "Main",
        },
    )
    assert denied_admin.status_code == 403


def test_depot_hierarchy_management_crud_and_validation(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    hierarchy = client.get("/api/depot/hierarchy")
    assert hierarchy.status_code == 200
    payload = hierarchy.get_json()
    assert "warehouses" in payload and "zones" in payload and "bins" in payload

    created_wh = authed_post(
        client, "/api/depot/warehouses", json={"name": "Overflow Depot"}
    )
    assert created_wh.status_code == 201
    warehouse_id = created_wh.get_json()["id"]

    created_zone = authed_post(
        client,
        "/api/depot/zones",
        json={"warehouse_id": warehouse_id, "name": "Zone X"},
    )
    assert created_zone.status_code == 201
    zone_id = created_zone.get_json()["id"]

    bad_bin = authed_post(
        client,
        "/api/depot/bins",
        json={
            "zone_id": zone_id,
            "code": "X-01",
            "bin_type": "invalid",
            "status": "available",
            "capacity_cuft": 10,
            "capacity_lb": 100,
        },
    )
    assert bad_bin.status_code == 422

    created_bin = authed_post(
        client,
        "/api/depot/bins",
        json={
            "zone_id": zone_id,
            "code": "X-01",
            "bin_type": "secure",
            "status": "maintenance",
            "capacity_cuft": 10,
            "capacity_lb": 100,
        },
    )
    assert created_bin.status_code == 201
    bin_id = created_bin.get_json()["id"]

    meta_bad = authed_post(
        client, f"/api/depot/bins/{bin_id}/metadata", json={"status": "bad"}
    )
    assert meta_bad.status_code == 422
    meta_ok = authed_post(
        client,
        f"/api/depot/bins/{bin_id}/metadata",
        json={"status": "available", "bin_type": "cold"},
    )
    assert meta_ok.status_code == 200

    manage_page = client.get("/depot/manage")
    assert manage_page.status_code == 200
    assert b"Depot Hierarchy Manager" in manage_page.data


def test_depot_manage_ui_contains_operator_workflow_controls(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    page = client.get("/depot/manage")
    assert page.status_code == 200
    assert b"Freeze or Unfreeze Bin" in page.data
    assert b"Allocate Inventory" in page.data
    assert b"/api/depot/bins/" in page.data
    assert b"/api/security/nonce" in page.data
    assert b"inventory_adjust" in page.data
    assert b"/api/depot/allocate" in page.data


def test_operator_workflow_freeze_and_allocate_paths(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    missing_nonce = authed_post(
        client, "/api/depot/bins/1/freeze", data={"frozen": "1"}
    )
    assert missing_nonce.status_code == 409

    invalid_freeze = authed_post(
        client, "/api/depot/bins/1/freeze", data={"frozen": "bad"}
    )
    assert invalid_freeze.status_code == 409

    nonce_for_freeze = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    invalid_freeze_with_nonce = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "bad", "request_nonce": nonce_for_freeze},
    )
    assert invalid_freeze_with_nonce.status_code == 422

    freeze_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    frozen = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "1", "request_nonce": freeze_nonce},
    )
    assert frozen.status_code == 200

    replay = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "0", "request_nonce": freeze_nonce},
    )
    assert replay.status_code == 409

    booking_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    cross_action = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "0", "request_nonce": booking_nonce},
    )
    assert cross_action.status_code == 409

    nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    blocked_allocate = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": nonce,
            "bin_id": 1,
            "item_name": "BlockedCrate",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert blocked_allocate.status_code == 409

    thaw_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    unfrozen = authed_post(
        client,
        "/api/depot/bins/1/freeze",
        data={"frozen": "0", "request_nonce": thaw_nonce},
    )
    assert unfrozen.status_code == 200

    nonce_ok = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    allocated = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": nonce_ok,
            "bin_id": 1,
            "item_name": "WorkflowCrate",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert allocated.status_code == 200

    with app.app_context():
        found = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM inventory_items WHERE bin_id=1 AND item_name='WorkflowCrate'"
            )
            .fetchone()[0]
        )
        assert found >= 1


def test_note_object_level_authorization(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)
    create = authed_post(
        client,
        "/api/notes",
        json={"title": "Agent Note", "content_md": "A", "note_type": "training"},
    )
    note_id = create.get_json()["id"]

    login_supervisor(client)
    denied = authed_post(
        client,
        "/api/notes",
        json={
            "id": note_id,
            "title": "Hijack",
            "content_md": "B",
            "note_type": "training",
        },
    )
    assert denied.status_code == 403

    with app.app_context():
        title = (
            app.get_db()
            .execute("SELECT title FROM notes WHERE id=?", (note_id,))
            .fetchone()[0]
        )
        assert title == "Agent Note"

    login_hr(client)
    allowed = authed_post(
        client,
        "/api/notes",
        json={
            "id": note_id,
            "title": "HR Override",
            "content_md": "C",
            "note_type": "training",
        },
    )
    assert allowed.status_code == 200


def test_kiosk_booking_hold_and_confirm(tmp_path):
    client, app = build_client(tmp_path)

    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )
        app.get_db().execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        app.get_db().commit()

    hold = client.post(
        "/api/kiosk/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "single",
            "bundle_days": 1,
            "kiosk_session_id": "ks-test-001",
        },
    )
    assert hold.status_code == 200
    hold_nonce = hold.get_json()["hold_nonce"]
    assert hold.get_json()["kiosk_session_id"] == "ks-test-001"

    nonce = client.post("/api/kiosk/security/nonce", data={"action": "booking_confirm"})
    assert nonce.status_code == 200

    confirm = client.post(
        "/api/kiosk/bookings/confirm",
        json={
            "hold_nonce": hold_nonce,
            "request_nonce": nonce.get_json()["nonce"],
            "contact": "kiosk@rider.local",
            "kiosk_session_id": "ks-test-001",
        },
    )
    assert confirm.status_code == 200
    assert confirm.get_json()["ok"] is True
    assert confirm.get_json()["kiosk_session_id"] == "ks-test-001"

    with app.app_context():
        db = app.get_db()
        hold_row = db.execute(
            "SELECT kiosk_session_id,status FROM seat_holds WHERE nonce=?",
            (hold_nonce,),
        ).fetchone()
        booking_row = db.execute(
            "SELECT kiosk_session_id FROM bookings WHERE user_id=(SELECT id FROM users WHERE username='kiosk_rider') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        event_row = db.execute(
            "SELECT metadata FROM analytics_events WHERE event_type='booking_confirmed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert hold_row["kiosk_session_id"] == "ks-test-001"
        assert hold_row["status"] == "converted"
        assert booking_row["kiosk_session_id"] == "ks-test-001"
        assert "ks-test-001" in event_row["metadata"]


def test_kiosk_session_id_fallback_generated_and_propagated(tmp_path):
    client, app = build_client(tmp_path)

    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )
        app.get_db().execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        app.get_db().commit()

    hold = client.post(
        "/api/kiosk/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "single",
            "bundle_days": 1,
        },
    )
    assert hold.status_code == 200
    payload = hold.get_json()
    assert payload["kiosk_session_id"]
    generated_session = payload["kiosk_session_id"]
    hold_nonce = payload["hold_nonce"]

    nonce = client.post("/api/kiosk/security/nonce", data={"action": "booking_confirm"})
    assert nonce.status_code == 200

    confirm = client.post(
        "/api/kiosk/bookings/confirm",
        json={
            "hold_nonce": hold_nonce,
            "request_nonce": nonce.get_json()["nonce"],
            "contact": "fallback@rider.local",
        },
    )
    assert confirm.status_code == 200
    assert confirm.get_json()["kiosk_session_id"] == generated_session

    with app.app_context():
        booking_row = (
            app.get_db()
            .execute(
                "SELECT kiosk_session_id FROM bookings WHERE nonce_used=?",
                (nonce.get_json()["nonce"],),
            )
            .fetchone()
        )
        assert booking_row["kiosk_session_id"] == generated_session


def test_notes_depot_scope_isolation(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    create_local = authed_post(
        client,
        "/api/notes",
        json={
            "title": "Main Depot SOP",
            "content_md": "Local",
            "note_type": "training",
        },
    )
    assert create_local.status_code == 200

    with app.app_context():
        db = app.get_db()
        owner_id = db.execute(
            "SELECT id FROM users WHERE username='agent01'"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO notes (title,content_md,note_type,owner_id,depot_scope,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (
                "Remote Only Note",
                "Hidden",
                "incident",
                owner_id,
                "Remote Depot",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        db.commit()

    page = client.get("/notes")
    assert page.status_code == 200
    assert b"Main Depot SOP" in page.data
    assert b"Remote Only Note" not in page.data


def test_notes_page_rollup_ui_section_present(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    page = client.get("/notes")
    assert page.status_code == 200
    assert b"Cross-Task Rollups" in page.data
    assert b"/api/notes/rollup" in page.data


def test_reports_page_access_and_content(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    denied = client.get("/reports")
    assert denied.status_code == 403

    login_hr(client)
    allowed = client.get("/reports")
    assert allowed.status_code == 200
    assert b"Governance Reports" in allowed.data
    assert b"Risk Event Breakdown" in allowed.data


def test_session_inactivity_timeout_redirects(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    with client.session_transaction() as sess:
        sess["last_seen"] = (datetime.now(UTC) - timedelta(minutes=31)).isoformat()
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_admin_user_create_enforces_password_policy(tmp_path):
    client, _app = build_client(tmp_path)
    login_admin(client)

    weak = authed_post(
        client,
        "/admin/users",
        json={
            "username": "weakuser",
            "password": "short",
            "role": "employee",
            "depot_assignment": "Depot A",
        },
    )
    assert weak.status_code == 422

    strong = authed_post(
        client,
        "/admin/users",
        json={
            "username": "newagent",
            "password": "LongEnoughPass!9",
            "role": "employee",
            "depot_assignment": "Depot A",
        },
    )
    assert strong.status_code == 201

    duplicate = authed_post(
        client,
        "/admin/users",
        json={
            "username": "newagent",
            "password": "LongEnoughPass!9",
            "role": "employee",
            "depot_assignment": "Depot A",
        },
    )
    assert duplicate.status_code == 409


def test_session_cookie_security_flags_present_on_login(tmp_path):
    previous = {
        "METROOPS_DB_PATH": os.environ.get("METROOPS_DB_PATH"),
        "METROOPS_KEY_PATH": os.environ.get("METROOPS_KEY_PATH"),
        "METROOPS_RUNTIME_ENV": os.environ.get("METROOPS_RUNTIME_ENV"),
        "DISABLE_TLS_ENFORCEMENT": os.environ.get("DISABLE_TLS_ENFORCEMENT"),
        "SESSION_COOKIE_SECURE": os.environ.get("SESSION_COOKIE_SECURE"),
    }
    os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_cookie.db")
    os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_cookie.key")
    os.environ["METROOPS_RUNTIME_ENV"] = "test"
    os.environ["DISABLE_TLS_ENFORCEMENT"] = "0"
    os.environ["SESSION_COOKIE_SECURE"] = "1"
    module = importlib.import_module("app.app")
    module = importlib.reload(module)
    app = module.create_app()
    app.testing = False
    app.init_db()
    client = app.test_client()
    response = client.post(
        "/login",
        data={"username": "agent01", "password": "MetroOpsPass!01"},
        base_url="https://localhost",
        follow_redirects=False,
    )
    assert response.status_code == 302
    cookie = response.headers.get("Set-Cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_development_http_mode_forces_non_secure_cookie_and_session_continuity(
    tmp_path,
):
    previous = {
        "METROOPS_DB_PATH": os.environ.get("METROOPS_DB_PATH"),
        "METROOPS_KEY_PATH": os.environ.get("METROOPS_KEY_PATH"),
        "METROOPS_RUNTIME_ENV": os.environ.get("METROOPS_RUNTIME_ENV"),
        "DISABLE_TLS_ENFORCEMENT": os.environ.get("DISABLE_TLS_ENFORCEMENT"),
        "SESSION_COOKIE_SECURE": os.environ.get("SESSION_COOKIE_SECURE"),
    }
    try:
        os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_http_dev.db")
        os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_http_dev.key")
        os.environ["METROOPS_RUNTIME_ENV"] = "development"
        os.environ["DISABLE_TLS_ENFORCEMENT"] = "1"
        os.environ["SESSION_COOKIE_SECURE"] = "1"
        module = importlib.import_module("app.app")
        module = importlib.reload(module)
        app = module.create_app()
        app.testing = False
        app.init_db()
        client = app.test_client()

        login = client.post(
            "/login",
            data={"username": "agent01", "password": "MetroOpsPass!01"},
            follow_redirects=False,
        )
        assert login.status_code == 302
        cookie = login.headers.get("Set-Cookie", "")
        assert "Secure" not in cookie

        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_tls_enforcement_login_lockout_experiment_and_analytics(tmp_path):
    os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_tls.db")
    os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_tls.key")
    os.environ["METROOPS_RUNTIME_ENV"] = "test"
    os.environ["DISABLE_TLS_ENFORCEMENT"] = "0"
    module = importlib.import_module("app.app")
    module = importlib.reload(module)
    app = module.create_app()
    app.testing = False
    app.config["DISABLE_TLS_ENFORCEMENT"] = False
    app.init_db()
    client = app.test_client()

    no_tls = client.get("/login")
    assert no_tls.status_code == 426

    secure = client.post(
        "/login",
        data={"username": "agent01", "password": "wrong-password"},
        base_url="https://localhost",
    )
    assert secure.status_code == 302
    for _ in range(4):
        resp = client.post(
            "/login",
            data={"username": "agent01", "password": "wrong-password"},
            base_url="https://localhost",
        )
        assert resp.status_code == 302
    locked = client.post(
        "/login",
        data={"username": "agent01", "password": "MetroOpsPass!01"},
        base_url="https://localhost",
    )
    assert locked.status_code == 302

    with app.app_context():
        lockout_until = (
            app.get_db()
            .execute("SELECT lockout_until FROM users WHERE username='agent01'")
            .fetchone()[0]
        )
        assert lockout_until is not None
        assert datetime.fromisoformat(lockout_until) > datetime.now(UTC)

    supervisor_login = client.post(
        "/login",
        data={"username": "supervisor01", "password": "MetroOpsPass!02"},
        base_url="https://localhost",
    )
    assert supervisor_login.status_code == 302

    assign = client.get(
        "/api/experiments/assign/suggested-times", base_url="https://localhost"
    )
    assert assign.status_code == 200
    payload = assign.get_json()
    assert payload["variant"] in ("A", "B")
    assert payload["label"] in ("Version A", "Version B")

    with app.app_context():
        db = app.get_db()
        now = datetime.now(UTC).isoformat()
        db.execute(
            "INSERT INTO analytics_events (user_id,event_type,created_at,metadata) VALUES (?,?,?,?)",
            (2, "rec_impression", now, "{}"),
        )
        db.execute(
            "INSERT INTO analytics_events (user_id,event_type,created_at,metadata) VALUES (?,?,?,?)",
            (2, "rec_click", now, "{}"),
        )
        db.execute(
            "INSERT INTO analytics_events (user_id,event_type,created_at,metadata) VALUES (?,?,?,?)",
            (2, "booking_confirmed", now, "{}"),
        )
        db.execute(
            "INSERT INTO ranking_samples (relevant,recommended,ndcg,covered,diverse,created_at) VALUES (?,?,?,?,?,?)",
            (1, 1, 0.9, 1, 1, now),
        )
        db.commit()

    metrics = client.get("/analyst/metrics", base_url="https://localhost")
    assert metrics.status_code == 200
    assert b"CTR" in metrics.data
    assert b"1.0" in metrics.data


def test_production_runtime_rejects_tls_disable_startup(tmp_path):
    previous = {
        "METROOPS_RUNTIME_ENV": os.environ.get("METROOPS_RUNTIME_ENV"),
        "DISABLE_TLS_ENFORCEMENT": os.environ.get("DISABLE_TLS_ENFORCEMENT"),
        "METROOPS_DB_PATH": os.environ.get("METROOPS_DB_PATH"),
        "METROOPS_KEY_PATH": os.environ.get("METROOPS_KEY_PATH"),
        "FLASK_SECRET": os.environ.get("FLASK_SECRET"),
    }
    try:
        os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_tls_policy_prod.db")
        os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_tls_policy_prod.key")
        os.environ["METROOPS_RUNTIME_ENV"] = "production"
        os.environ["FLASK_SECRET"] = "prod-test-secret"
        os.environ["DISABLE_TLS_ENFORCEMENT"] = "1"

        module = importlib.import_module("app.app")
        with pytest.raises(
            RuntimeError, match="allowed only in development/test/local"
        ):
            importlib.reload(module)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_development_runtime_allows_tls_disable_with_warning(tmp_path, caplog):
    previous = {
        "METROOPS_RUNTIME_ENV": os.environ.get("METROOPS_RUNTIME_ENV"),
        "DISABLE_TLS_ENFORCEMENT": os.environ.get("DISABLE_TLS_ENFORCEMENT"),
        "METROOPS_DB_PATH": os.environ.get("METROOPS_DB_PATH"),
        "METROOPS_KEY_PATH": os.environ.get("METROOPS_KEY_PATH"),
    }
    try:
        os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_tls_policy_dev.db")
        os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_tls_policy_dev.key")
        os.environ["METROOPS_RUNTIME_ENV"] = "development"
        os.environ["DISABLE_TLS_ENFORCEMENT"] = "1"

        caplog.set_level(logging.WARNING)
        module = importlib.import_module("app.app")
        module = importlib.reload(module)
        app = module.create_app()
        app.testing = False
        app.init_db()
        client = app.test_client()

        response = client.get("/login")
        assert response.status_code == 200
        logs = "\n".join(record.getMessage() for record in caplog.records)
        assert "TLS enforcement disabled" in logs
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_experiment_assignment_population_near_5050(tmp_path):
    client, app = build_client(tmp_path)
    with app.app_context():
        db = app.get_db()
        now = datetime.now(UTC).isoformat()
        seed_hash = "pbkdf2:sha256:600000$seed$hash"
        rows = [
            (f"load_user_{i}", seed_hash, "employee", "Main Depot", now)
            for i in range(1, 1201)
        ]
        db.executemany(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            rows,
        )
        db.commit()
        user_ids = [
            r[0]
            for r in db.execute(
                "SELECT id FROM users WHERE username LIKE 'load_user_%' ORDER BY id"
            ).fetchall()
        ]

    a_count = 0
    b_count = 0
    for uid in user_ids:
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["last_seen"] = datetime.now(UTC).isoformat()
            sess["csrf_token"] = "seed"
        assignment = client.get("/api/experiments/assign/suggested-times")
        assert assignment.status_code == 200
        variant = assignment.get_json()["variant"]
        if variant == "A":
            a_count += 1
        else:
            b_count += 1

    total = a_count + b_count
    a_ratio = a_count / total
    b_ratio = b_count / total
    assert 0.45 <= a_ratio <= 0.55
    assert 0.45 <= b_ratio <= 0.55


def test_experiment_control_update_requires_permission_and_writes_audit(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    denied = authed_post(
        client,
        "/supervisor/experiments/1",
        data={
            "enabled": "1",
            "label_a": "Fast",
            "label_b": "Stable",
            "split_a_percent": "70",
        },
    )
    assert denied.status_code == 403

    login_supervisor(client)
    updated = authed_post(
        client,
        "/supervisor/experiments/1",
        data={
            "enabled": "0",
            "label_a": "Pilot A",
            "label_b": "Pilot B",
            "split_a_percent": "50",
        },
        follow_redirects=False,
    )
    assert updated.status_code == 302

    with app.app_context():
        db = app.get_db()
        exp = db.execute(
            "SELECT enabled,label_a,label_b,split_a_percent FROM experiments WHERE id=1"
        ).fetchone()
        assert exp["enabled"] == 0
        assert exp["label_a"] == "Pilot A"
        assert exp["label_b"] == "Pilot B"
        assert exp["split_a_percent"] == 50
        audit = db.execute(
            "SELECT COUNT(*) FROM experiment_audit_log WHERE experiment_id=1 AND changed_by=2"
        ).fetchone()[0]
        assert audit >= 1


def test_experiment_rejects_non_50_split_policy_update(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    rejected = authed_post(
        client,
        "/supervisor/experiments/1",
        data={
            "enabled": "1",
            "label_a": "Version A",
            "label_b": "Version B",
            "split_a_percent": "80",
        },
    )
    assert rejected.status_code == 422
    assert "fixed policy" in rejected.get_json()["error"]

    with app.app_context():
        split = (
            app.get_db()
            .execute("SELECT split_a_percent FROM experiments WHERE id=1")
            .fetchone()[0]
        )
        assert split == 50


def test_experiment_ui_shows_fixed_split_policy(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    page = client.get("/supervisor/experiments")
    assert page.status_code == 200
    assert b"50% / B: 50% (fixed by policy)" in page.data
    assert b'name="split_a_percent"' not in page.data


def test_experiment_assignment_policy_stays_near_5050(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    updated = authed_post(
        client,
        "/supervisor/experiments/1",
        data={
            "enabled": "1",
            "label_a": "Version A",
            "label_b": "Version B",
            "split_a_percent": "50",
        },
    )
    assert updated.status_code == 302

    with app.app_context():
        db = app.get_db()
        now = datetime.now(UTC).isoformat()
        seed_hash = "pbkdf2:sha256:600000$seed$hash"
        rows = [
            (f"split_user_{i}", seed_hash, "employee", "Main Depot", now)
            for i in range(1, 801)
        ]
        db.executemany(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            rows,
        )
        db.commit()
        user_ids = [
            r[0]
            for r in db.execute(
                "SELECT id FROM users WHERE username LIKE 'split_user_%' ORDER BY id"
            ).fetchall()
        ]

    a_count = 0
    b_count = 0
    for uid in user_ids:
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["last_seen"] = datetime.now(UTC).isoformat()
            sess["csrf_token"] = "seed"
        assignment = client.get("/api/experiments/assign/suggested-times")
        assert assignment.status_code == 200
        variant = assignment.get_json()["variant"]
        if variant == "A":
            a_count += 1
        else:
            b_count += 1

    total = a_count + b_count
    a_ratio = a_count / total
    b_ratio = b_count / total
    assert 0.45 <= a_ratio <= 0.55
    assert 0.45 <= b_ratio <= 0.55


def test_recommendation_telemetry_event_writes_impression_and_click(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    impression = authed_post(
        client,
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_impression",
            "widget_key": "suggested-times",
            "variant_label": "Version A",
        },
    )
    assert impression.status_code == 201

    click = authed_post(
        client,
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_click",
            "widget_key": "suggested-times",
            "variant_label": "Version A",
        },
    )
    assert click.status_code == 201

    with app.app_context():
        rows = (
            app.get_db()
            .execute(
                "SELECT event_type,widget_key,variant FROM analytics_events WHERE user_id=2 AND event_type IN ('rec_impression','rec_click') ORDER BY id"
            )
            .fetchall()
        )
        assert len(rows) >= 2
        assert rows[-2]["event_type"] == "rec_impression"
        assert rows[-2]["widget_key"] == "suggested-times"
        assert rows[-2]["variant"] == "Version A"
        assert rows[-1]["event_type"] == "rec_click"


def test_recommendation_telemetry_event_rejects_malformed_payload(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    bad_event_type = authed_post(
        client,
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_open",
            "widget_key": "suggested-times",
            "variant_label": "Version A",
        },
    )
    assert bad_event_type.status_code == 400

    bad_widget = authed_post(
        client,
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_impression",
            "widget_key": "unknown-widget",
            "variant_label": "Version A",
        },
    )
    assert bad_widget.status_code == 400

    bad_label = authed_post(
        client,
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_click",
            "widget_key": "suggested-times",
            "variant_label": "Unknown Label",
        },
    )
    assert bad_label.status_code == 400


def test_recommendation_telemetry_auth_and_rate_limit(tmp_path):
    client, _app = build_client(tmp_path)

    unauth = client.post(
        "/api/analytics/recommendation-event",
        json={
            "event_type": "rec_impression",
            "widget_key": "suggested-times",
            "variant_label": "Version A",
        },
    )
    assert unauth.status_code == 302

    login_supervisor(client)
    limited = None
    for _ in range(41):
        limited = authed_post(
            client,
            "/api/analytics/recommendation-event",
            json={
                "event_type": "rec_click",
                "widget_key": "suggested-times",
                "variant_label": "Version A",
            },
        )
    assert limited is not None
    assert limited.status_code == 429


def test_anomaly_notes_features_social_and_masking(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    csv_data = "vehicle_id,route_id,stop_sequence,speed_mph,ping_time,lat,lon\nV1,1,1,10,2026-01-01T00:00:00+00:00,0,0\nV1,1,1,100,2026-01-01T00:01:00+00:00,0,0\n"
    upload = authed_post(
        client,
        "/api/vehicle-pings/upload",
        data={"file": (BytesIO(csv_data.encode("utf-8")), "pings.csv")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200
    with app.app_context():
        risk_count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='impossible_speed_jump'"
            )
            .fetchone()[0]
        )
        assert risk_count >= 1

    note_a = authed_post(
        client,
        "/api/notes",
        json={
            "title": "N1",
            "content_md": "one\n<script>alert(1)</script>\n[bad](javascript:alert(2))",
            "note_type": "training",
        },
    ).get_json()["id"]
    note_b = authed_post(
        client,
        "/api/notes",
        json={"title": "N2", "content_md": "two", "note_type": "incident"},
    ).get_json()["id"]

    preview = client.get(f"/api/notes/{note_a}/render")
    assert preview.status_code == 200
    html = preview.get_json()["html"]
    assert "<p>" in html or "<br>" in html
    assert "<script" not in html
    assert "javascript:" not in html

    link = authed_post(
        client,
        "/api/notes/link",
        json={"from_note_id": note_a, "to_note_id": note_b, "link_type": "related"},
    )
    assert link.status_code == 200

    upd = authed_post(
        client,
        "/api/notes",
        json={
            "id": note_a,
            "title": "N1-v2",
            "content_md": "two",
            "note_type": "training",
        },
    )
    assert upd.status_code == 200

    versions = client.get(f"/api/notes/{note_a}/versions")
    assert versions.status_code == 200
    versions_payload = versions.get_json()
    assert len(versions_payload) >= 1
    target_version = versions_payload[0]["version_no"]

    rollback = authed_post(client, f"/api/notes/{note_a}/rollback/{target_version}")
    assert rollback.status_code == 200

    attach = authed_post(
        client,
        f"/api/notes/{note_a}/attachments",
        data={"file": (BytesIO(b"hello"), "doc.txt")},
        content_type="multipart/form-data",
    )
    assert attach.status_code == 200

    login_agent(client)

    follow = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "follow"}
    )
    assert follow.status_code == 200
    block = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "block"}
    )
    assert block.status_code == 200
    favorite = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "favorite"}
    )
    assert favorite.status_code == 200
    like = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "like"}
    )
    assert like.status_code == 200
    report = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "report"}
    )
    assert report.status_code == 200

    with app.app_context():
        rel_count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM relationships WHERE user_a=1 AND user_b=2 AND relation IN ('follow','block','favorite','like','report')"
            )
            .fetchone()[0]
        )
        assert rel_count == 5

    with app.app_context():
        encrypted = app.fernet.encrypt(b"FACE123456")
        app.get_db().execute(
            "UPDATE users SET face_identifier_encrypted=? WHERE id=?", (encrypted, 1)
        )
        app.get_db().execute(
            "INSERT OR IGNORE INTO relationships (user_a,user_b,relation,created_at) VALUES (?,?,?,?)",
            (2, 1, "follow", datetime.now(UTC).isoformat()),
        )
        app.get_db().execute(
            "INSERT OR IGNORE INTO relationships (user_a,user_b,relation,created_at) VALUES (?,?,?,?)",
            (1, 2, "follow", datetime.now(UTC).isoformat()),
        )
        app.get_db().commit()

    profile = client.get("/profiles/1")
    assert profile.status_code == 200
    assert b"***" in profile.data


def test_vehicle_ping_ingest_requires_ops_permission(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    csv_data = "vehicle_id,route_id,stop_sequence,speed_mph,ping_time,lat,lon\nV1,1,1,10,2026-01-01T00:00:00+00:00,0,0\n"
    denied = authed_post(
        client,
        "/api/vehicle-pings/upload",
        data={"file": (BytesIO(csv_data.encode("utf-8")), "pings.csv")},
        content_type="multipart/form-data",
    )
    assert denied.status_code == 403

    login_supervisor(client)
    allowed = authed_post(
        client,
        "/api/vehicle-pings/upload",
        data={"file": (BytesIO(csv_data.encode("utf-8")), "pings.csv")},
        content_type="multipart/form-data",
    )
    assert allowed.status_code == 200


def test_geospatial_implied_speed_anomaly_detection(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    csv_data = (
        "vehicle_id,route_id,stop_sequence,speed_mph,ping_time,lat,lon\n"
        "V2,1,1,20,2026-01-01T00:00:00+00:00,40.0,-74.0\n"
        "V2,1,1,20,2026-01-01T00:01:00+00:00,41.0,-74.0\n"
    )
    upload = authed_post(
        client,
        "/api/vehicle-pings/upload",
        data={"file": (BytesIO(csv_data.encode("utf-8")), "pings_geo.csv")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200
    with app.app_context():
        rows = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='impossible_speed_jump' AND details LIKE '%implied_mph=%'"
            )
            .fetchone()[0]
        )
        assert rows >= 1


def test_gps_anomaly_threshold_not_triggered_under_85_mph(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    csv_data = (
        "vehicle_id,route_id,stop_sequence,speed_mph,ping_time,lat,lon\n"
        "V3,1,1,20,2026-01-01T00:00:00+00:00,40.0,-74.0\n"
        "V3,1,1,20,2026-01-01T01:00:00+00:00,40.7,-74.0\n"
    )
    upload = authed_post(
        client,
        "/api/vehicle-pings/upload",
        data={"file": (BytesIO(csv_data.encode("utf-8")), "pings_safe_geo.csv")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200

    with app.app_context():
        rows = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='impossible_speed_jump' AND details LIKE 'vehicle=V3%'"
            )
            .fetchone()[0]
        )
        assert rows == 0


def test_authenticated_html_routes_send_no_store_cache_headers(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert (
        dashboard.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"
    )
    assert dashboard.headers.get("Pragma") == "no-cache"
    assert dashboard.headers.get("Expires") == "0"


def test_lan_gateway_ingestion_and_csrf_protection(tmp_path):
    os.environ["METROOPS_GATEWAY_TOKEN"] = "gateway-secret"
    client, app = build_client(tmp_path)
    login_agent(client)

    missing_csrf = client.post(
        "/api/notes",
        json={"title": "Should fail", "content_md": "x", "note_type": "training"},
    )
    assert missing_csrf.status_code == 403

    bad_gateway = client.post("/api/vehicle-pings/gateway", json={"pings": []})
    assert bad_gateway.status_code == 403

    good_gateway = client.post(
        "/api/vehicle-pings/gateway",
        json={
            "pings": [
                {
                    "vehicle_id": "GW-1",
                    "route_id": 1,
                    "stop_sequence": 1,
                    "speed_mph": 22,
                    "ping_time": datetime.now(UTC).isoformat(),
                    "lat": 0,
                    "lon": 0,
                }
            ]
        },
        headers={"X-Gateway-Token": "gateway-secret"},
    )
    assert good_gateway.status_code == 200
    with app.app_context():
        row = (
            app.get_db()
            .execute(
                "SELECT source FROM vehicle_pings WHERE vehicle_id='GW-1' ORDER BY id DESC LIMIT 1"
            )
            .fetchone()
        )
        assert row is not None
        assert row["source"] == "lan_gateway"


def test_placeholder_gateway_token_disables_lan_ingestion(tmp_path, caplog):
    previous_token = os.environ.get("METROOPS_GATEWAY_TOKEN")
    os.environ["METROOPS_GATEWAY_TOKEN"] = "replace-me-for-production"
    try:
        caplog.set_level(logging.WARNING)
        client, _app = build_client(tmp_path)

        blocked = client.post(
            "/api/vehicle-pings/gateway",
            json={"pings": []},
            headers={"X-Gateway-Token": "replace-me-for-production"},
        )
        assert blocked.status_code == 503
        assert "disabled" in blocked.get_json()["error"].lower()

        logs = "\n".join(record.getMessage() for record in caplog.records)
        assert "placeholder-like value" in logs
    finally:
        if previous_token is None:
            os.environ.pop("METROOPS_GATEWAY_TOKEN", None)
        else:
            os.environ["METROOPS_GATEWAY_TOKEN"] = previous_token


def test_kiosk_nonce_throttling_and_risk_event(tmp_path):
    client, app = build_client(tmp_path)
    for _ in range(30):
        ok = client.post(
            "/api/kiosk/security/nonce",
            data={"action": "booking_confirm"},
            headers={"X-Kiosk-Actor": "abuse-nonce"},
        )
        assert ok.status_code == 200
    throttled = client.post(
        "/api/kiosk/security/nonce",
        data={"action": "booking_confirm"},
        headers={"X-Kiosk-Actor": "abuse-nonce"},
    )
    assert throttled.status_code == 429
    assert "retry_after_seconds" in throttled.get_json()

    with app.app_context():
        count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='kiosk_abuse_throttle' AND details LIKE '%kiosk_nonce%'"
            )
            .fetchone()[0]
        )
        assert count >= 1


def test_kiosk_hold_throttling_and_normal_flow_under_limit(tmp_path):
    client, app = build_client(tmp_path)
    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        db.execute(
            "UPDATE departures SET departure_time=?, total_seats=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=4)).isoformat(), 500, dep_id),
        )
        db.commit()

    normal_hold = client.post(
        "/api/kiosk/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "single",
            "bundle_days": 1,
        },
        headers={"X-Kiosk-Actor": "normal-flow"},
    )
    assert normal_hold.status_code == 200

    for _ in range(20):
        response = client.post(
            "/api/kiosk/bookings/hold",
            json={
                "departure_id": dep_id,
                "seats": 1,
                "product_type": "single",
                "bundle_days": 1,
            },
            headers={"X-Kiosk-Actor": "abuse-hold"},
        )
        assert response.status_code == 200

    throttled = client.post(
        "/api/kiosk/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "single",
            "bundle_days": 1,
        },
        headers={"X-Kiosk-Actor": "abuse-hold"},
    )
    assert throttled.status_code == 429

    with app.app_context():
        risk_count = (
            app.get_db()
            .execute(
                "SELECT COUNT(*) FROM risk_events WHERE event_type='kiosk_abuse_throttle' AND details LIKE '%kiosk_hold%'"
            )
            .fetchone()[0]
        )
        assert risk_count >= 1


def test_malformed_payloads_return_4xx_not_500(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    missing_relation = authed_post(
        client, "/api/social/action", json={"target_user_id": 2}
    )
    assert missing_relation.status_code == 422

    missing_target = authed_post(
        client,
        "/api/social/action",
        json={"target_user_id": 999999, "relation": "follow"},
    )
    assert missing_target.status_code == 404

    bad_relation = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "INVALID"}
    )
    assert bad_relation.status_code == 422

    nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    bad_allocate = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": nonce,
            "bin_id": "bad",
            "volume_cuft": "x",
            "weight_lb": "y",
        },
    )
    assert bad_allocate.status_code == 422


def test_note_link_semantics_require_incident_training_pairs(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    t1 = authed_post(
        client,
        "/api/notes",
        json={"title": "T1", "content_md": "x", "note_type": "training"},
    ).get_json()["id"]
    t2 = authed_post(
        client,
        "/api/notes",
        json={"title": "T2", "content_md": "x", "note_type": "training"},
    ).get_json()["id"]
    i1 = authed_post(
        client,
        "/api/notes",
        json={"title": "I1", "content_md": "x", "note_type": "incident"},
    ).get_json()["id"]
    i2 = authed_post(
        client,
        "/api/notes",
        json={"title": "I2", "content_md": "x", "note_type": "incident"},
    ).get_json()["id"]

    tt = authed_post(
        client,
        "/api/notes/link",
        json={"from_note_id": t1, "to_note_id": t2, "link_type": "related"},
    )
    assert tt.status_code == 422
    ii = authed_post(
        client,
        "/api/notes/link",
        json={"from_note_id": i1, "to_note_id": i2, "link_type": "related"},
    )
    assert ii.status_code == 422
    ti = authed_post(
        client,
        "/api/notes/link",
        json={"from_note_id": t1, "to_note_id": i1, "link_type": "related"},
    )
    assert ti.status_code == 200


def test_notes_rollup_requires_notes_read_permission(tmp_path):
    client, app = build_client(tmp_path)

    unauthenticated = client.get("/api/notes/rollup")
    assert unauthenticated.status_code == 302

    login_agent(client)
    allowed = client.get("/api/notes/rollup")
    assert allowed.status_code == 200

    with app.app_context():
        app.get_db().execute(
            "DELETE FROM permissions WHERE role='employee' AND permission='notes:read'"
        )
        app.get_db().commit()

    denied = client.get("/api/notes/rollup")
    assert denied.status_code == 403


def test_nonce_cross_action_misuse_rejected(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )
        app.get_db().execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        app.get_db().commit()

    hold = authed_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert hold.status_code == 200

    valid_inventory_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    valid_inventory_adjust = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": valid_inventory_nonce,
            "bin_id": 1,
            "item_name": "ValidNonce",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert valid_inventory_adjust.status_code == 200

    replay_inventory_nonce = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": valid_inventory_nonce,
            "bin_id": 1,
            "item_name": "ReplayNonce",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert replay_inventory_nonce.status_code == 409

    booking_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    inventory_with_booking_nonce = authed_post(
        client,
        "/api/depot/allocate",
        json={
            "request_nonce": booking_nonce,
            "bin_id": 1,
            "item_name": "CrossAction",
            "volume_cuft": 1,
            "weight_lb": 1,
        },
    )
    assert inventory_with_booking_nonce.status_code == 409

    inventory_nonce = authed_post(
        client, "/api/security/nonce", data={"action": "inventory_adjust"}
    ).get_json()["nonce"]
    booking_with_inventory_nonce = authed_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold.get_json()["hold_nonce"],
            "request_nonce": inventory_nonce,
            "contact": "none@metro.local",
        },
    )
    assert booking_with_inventory_nonce.status_code == 409


def test_booking_rule_config_is_db_backed_and_audited(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)

    kiosk_before = client.get("/kiosk")
    assert kiosk_before.status_code == 200
    assert b"Hold Seat (8 min)" in kiosk_before.data

    initial = client.get("/api/config/booking-rules")
    assert initial.status_code == 200
    assert initial.get_json()["seat_hold_timeout_minutes"] == 8

    updated = authed_post(
        client,
        "/api/config/booking-rules",
        json={
            "booking_min_advance_hours": 3,
            "booking_max_horizon_days": 20,
            "commuter_bundle_min_days": 4,
            "seat_hold_timeout_minutes": 5,
        },
    )
    assert updated.status_code == 200
    assert updated.get_json()["rules"]["seat_hold_timeout_minutes"] == 5

    kiosk_after = client.get("/kiosk")
    assert kiosk_after.status_code == 200
    assert b"Hold Seat (5 min)" in kiosk_after.data

    with app.app_context():
        count = (
            app.get_db().execute("SELECT COUNT(*) FROM config_audit_log").fetchone()[0]
        )
        assert count >= 4

    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )
        app.get_db().execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3, minutes=5)).isoformat(), dep_id),
        )
        app.get_db().commit()

    bundle_reject = authed_post(
        client,
        "/api/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "commuter_bundle",
            "bundle_days": 3,
        },
    )
    assert bundle_reject.status_code == 422
    assert "minimum 4 days" in bundle_reject.get_json()["error"]

    hold = authed_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert hold.status_code == 200

    with app.app_context():
        expires_at = (
            app.get_db()
            .execute(
                "SELECT expires_at FROM seat_holds WHERE nonce=?",
                (hold.get_json()["hold_nonce"],),
            )
            .fetchone()[0]
        )
        delta = datetime.fromisoformat(expires_at) - datetime.now(UTC)
        assert 4 <= delta.total_seconds() / 60 <= 6


def test_auth_status_matrix_and_sensitive_field_non_leakage(tmp_path, caplog):
    client, app = build_client(tmp_path)

    unauth = client.get("/api/config/booking-rules")
    assert unauth.status_code == 302

    login_agent(client)
    forbidden = client.get("/api/config/booking-rules")
    assert forbidden.status_code == 403

    not_found = authed_post(
        client,
        "/api/social/action",
        json={"target_user_id": 999999, "relation": "follow"},
    )
    assert not_found.status_code == 404

    invalid = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "INVALID"}
    )
    assert invalid.status_code == 422

    throttle_first = client.get("/api/heartbeat?screen=matrix")
    assert throttle_first.status_code == 200
    throttle_second = client.get("/api/heartbeat?screen=matrix")
    assert throttle_second.status_code == 429

    caplog.set_level(logging.INFO)
    with app.app_context():
        dep_id = (
            app.get_db()
            .execute("SELECT id FROM departures ORDER BY id LIMIT 1")
            .fetchone()[0]
        )
        app.get_db().execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        app.get_db().commit()

    hold = authed_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    nonce = authed_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    contact_secret = "private-contact@example.com"
    confirmed = authed_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold.get_json()["hold_nonce"],
            "request_nonce": nonce,
            "contact": contact_secret,
        },
    )
    assert confirmed.status_code == 200
    body = confirmed.get_data(as_text=True)
    assert contact_secret not in body
    assert "nonce" not in body.lower()
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert contact_secret not in logs


def test_analytics_recall_differs_from_precision(tmp_path):
    client, app = build_client(tmp_path)
    login_supervisor(client)
    with app.app_context():
        db = app.get_db()
        now = datetime.now(UTC).isoformat()
        db.execute("DELETE FROM ranking_samples")
        db.execute(
            "INSERT INTO ranking_samples (relevant,recommended,ndcg,covered,diverse,created_at) VALUES (?,?,?,?,?,?)",
            (1, 1, 1.0, 1, 1, now),
        )
        db.execute(
            "INSERT INTO ranking_samples (relevant,recommended,ndcg,covered,diverse,created_at) VALUES (?,?,?,?,?,?)",
            (1, 0, 0.3, 1, 0, now),
        )
        db.commit()

    page = client.get("/analyst/metrics")
    assert page.status_code == 200
    assert b"Precision: 1.0" in page.data
    assert b"Recall: 0.5" in page.data


def test_depot_bin_rules_are_persistence_configurable(tmp_path):
    client, _app = build_client(tmp_path)
    login_supervisor(client)

    rules = client.get("/api/depot/bin-rules")
    assert rules.status_code == 200

    deactivate_standard = authed_post(
        client,
        "/api/depot/bin-rules",
        json={"rule_type": "bin_type", "rule_value": "standard", "is_active": 0},
    )
    assert deactivate_standard.status_code == 200

    create_rejected = authed_post(
        client,
        "/api/depot/bins",
        json={
            "zone_id": 1,
            "code": "RULE-STD-1",
            "bin_type": "standard",
            "status": "available",
            "capacity_cuft": 10,
            "capacity_lb": 10,
        },
    )
    assert create_rejected.status_code == 422

    add_new_type = authed_post(
        client,
        "/api/depot/bin-rules",
        json={"rule_type": "bin_type", "rule_value": "oversize", "is_active": 1},
    )
    assert add_new_type.status_code == 200

    create_allowed = authed_post(
        client,
        "/api/depot/bins",
        json={
            "zone_id": 1,
            "code": "RULE-OVR-1",
            "bin_type": "oversize",
            "status": "available",
            "capacity_cuft": 10,
            "capacity_lb": 10,
        },
    )
    assert create_allowed.status_code == 201


def test_safe_default_debug_mode(tmp_path):
    os.environ.pop("FLASK_DEBUG", None)
    _client, app = build_client(tmp_path)
    assert app.debug is False


def test_face_identifier_logging_uses_mask_only(tmp_path, caplog):
    client, app = build_client(tmp_path)
    caplog.set_level(logging.INFO)
    login_agent(client)
    raw_identifier = "FACE-SECRET-9988"
    with app.app_context():
        encrypted = app.fernet.encrypt(raw_identifier.encode("utf-8"))
        app.get_db().execute(
            "UPDATE users SET face_identifier_encrypted=? WHERE id=?", (encrypted, 1)
        )
        app.get_db().commit()

    response = client.get("/profiles/1")
    assert response.status_code == 200
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert raw_identifier not in logs
    assert "FA***88" in logs


def test_attachment_size_limit_and_unauthorized_matrix(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)

    note_id = authed_post(
        client,
        "/api/notes",
        json={"title": "Big Attach", "content_md": "x", "note_type": "training"},
    ).get_json()["id"]

    oversized = authed_post(
        client,
        f"/api/notes/{note_id}/attachments",
        data={"file": (BytesIO(b"a" * (20 * 1024 * 1024 + 1)), "big.bin")},
        content_type="multipart/form-data",
    )
    assert oversized.status_code == 413

    exp_denied = client.get("/supervisor/experiments")
    assert exp_denied.status_code == 403
    metrics_denied = client.get("/analyst/metrics")
    assert metrics_denied.status_code == 403
    admin_denied = authed_post(
        client,
        "/admin/users",
        json={
            "username": "x",
            "password": "LongEnoughPass!9",
            "role": "employee",
            "depot_assignment": "A",
        },
    )
    assert admin_denied.status_code == 403

    logout_denied = client.post("/logout")
    assert logout_denied.status_code == 403


def test_blocked_profile_visibility_denied(tmp_path):
    client, _app = build_client(tmp_path)
    login_agent(client)
    block = authed_post(
        client, "/api/social/action", json={"target_user_id": 2, "relation": "block"}
    )
    assert block.status_code == 200

    login_supervisor(client)
    denied = client.get("/profiles/1")
    assert denied.status_code == 403
