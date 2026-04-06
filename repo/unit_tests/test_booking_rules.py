import importlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

UTC = timezone.utc


def build_client(tmp_path):
    os.environ["METROOPS_DB_PATH"] = str(tmp_path / "metroops_test.db")
    os.environ["METROOPS_KEY_PATH"] = str(tmp_path / "metroops_test.key")
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


def auth_post(client, url, **kwargs):
    with client.session_transaction() as sess:
        token = sess.get("csrf_token")
    headers = dict(kwargs.pop("headers", {}) or {})
    if token:
        headers["X-CSRF-Token"] = token
    return client.post(url, headers=headers, **kwargs)


def test_booking_window_and_inventory_lock(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        db.execute(
            "UPDATE departures SET departure_time=?, total_seats=1 WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        db.commit()

    first_hold = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert first_hold.status_code == 200

    second_hold = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert second_hold.status_code == 409
    assert second_hold.get_json()["error"] == "Insufficient seats"

    with app.app_context():
        db = app.get_db()
        db.execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(days=31)).isoformat(), dep_id),
        )
        db.commit()

    out_of_window = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert out_of_window.status_code == 422
    assert "more than 30 days" in out_of_window.get_json()["error"]

    with app.app_context():
        db = app.get_db()
        db.execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(minutes=90)).isoformat(), dep_id),
        )
        db.commit()

    too_soon = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    assert too_soon.status_code == 422
    assert "at least 2 hours" in too_soon.get_json()["error"]


def test_booking_confirm_nonce_and_bundle_rule(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        db.execute(
            "UPDATE departures SET departure_time=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=4)).isoformat(), dep_id),
        )
        db.commit()

    invalid_bundle = auth_post(
        client,
        "/api/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "commuter_bundle",
            "bundle_days": 2,
        },
    )
    assert invalid_bundle.status_code == 422

    hold = auth_post(
        client,
        "/api/bookings/hold",
        json={
            "departure_id": dep_id,
            "seats": 1,
            "product_type": "commuter_bundle",
            "bundle_days": 3,
        },
    )
    hold_json = hold.get_json()
    nonce_res = auth_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    )
    nonce = nonce_res.get_json()["nonce"]
    confirm = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold_json["hold_nonce"],
            "request_nonce": nonce,
            "contact": "rider@example.com",
        },
    )
    assert confirm.status_code == 200
    assert confirm.get_json()["ok"] is True

    replay = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold_json["hold_nonce"],
            "request_nonce": nonce,
            "contact": "rider@example.com",
        },
    )
    assert replay.status_code == 409


def test_nonce_expiry_hold_expiry_and_rate_plan_pricing(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        departure_time = (datetime.now(UTC) + timedelta(hours=5)).isoformat()
        db.execute(
            "UPDATE departures SET departure_time=?, base_price=? WHERE id=?",
            (departure_time, 20.0, dep_id),
        )
        db.execute("DELETE FROM rate_plans")
        dep_date = datetime.fromisoformat(departure_time).date().isoformat()
        db.execute(
            "INSERT INTO rate_plans (name,start_date,end_date,amount_delta) VALUES (?,?,?,?)",
            ("Test Delta", dep_date, dep_date, 5.0),
        )
        db.commit()

    hold = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 2}
    )
    assert hold.status_code == 200
    hold_nonce = hold.get_json()["hold_nonce"]

    nonce = auth_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    with app.app_context():
        app.get_db().execute(
            "UPDATE sessions_nonce SET expires_at=? WHERE nonce=?",
            ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(), nonce),
        )
        app.get_db().commit()
    expired_nonce = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold_nonce,
            "request_nonce": nonce,
            "contact": "rider@example.com",
        },
    )
    assert expired_nonce.status_code == 409

    with app.app_context():
        app.get_db().execute(
            "UPDATE seat_holds SET expires_at=? WHERE nonce=?",
            ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(), hold_nonce),
        )
        app.get_db().commit()

    nonce2 = auth_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    expired_hold = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold_nonce,
            "request_nonce": nonce2,
            "contact": "rider@example.com",
        },
    )
    assert expired_hold.status_code == 410

    fresh_hold = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    fresh_nonce = auth_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    confirmed = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": fresh_hold.get_json()["hold_nonce"],
            "request_nonce": fresh_nonce,
            "contact": "rider@example.com",
        },
    )
    assert confirmed.status_code == 200
    assert confirmed.get_json()["total_price"] == 25.0


def test_concurrent_holds_prevent_overbooking(tmp_path):
    client_a, app = build_client(tmp_path)
    client_b = app.test_client()
    login_agent(client_a)
    login_agent(client_b)

    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        db.execute(
            "UPDATE departures SET departure_time=?, total_seats=1 WHERE id=?",
            ((datetime.now(UTC) + timedelta(hours=3)).isoformat(), dep_id),
        )
        db.commit()

    def hold(client):
        return auth_post(
            client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(hold, [client_a, client_b]))

    assert sorted(results) == [200, 409]

    with app.app_context():
        db = app.get_db()
        remaining = db.execute(
            "SELECT total_seats - COALESCE((SELECT SUM(seats) FROM seat_holds WHERE departure_id=? AND status='active'),0) - COALESCE((SELECT SUM(seats) FROM bookings WHERE departure_id=? AND status='confirmed'),0) FROM departures WHERE id=?",
            (dep_id, dep_id, dep_id),
        ).fetchone()[0]
        assert remaining == 0


def test_login_lockout_persists_across_app_reload(tmp_path):
    client, app = build_client(tmp_path)

    for _ in range(5):
        bad = client.post(
            "/login",
            data={"username": "agent01", "password": "WrongPass!"},
            follow_redirects=False,
        )
        assert bad.status_code == 302

    locked = client.post(
        "/login",
        data={"username": "agent01", "password": "MetroOpsPass!01"},
        follow_redirects=False,
    )
    assert locked.status_code == 302
    assert "/login" in (locked.headers.get("Location") or "")

    with app.app_context():
        lockout_until = (
            app.get_db()
            .execute("SELECT lockout_until FROM users WHERE username='agent01'")
            .fetchone()[0]
        )
        assert lockout_until

    module = importlib.import_module("app.app")
    module = importlib.reload(module)
    app_reloaded = module.create_app()
    app_reloaded.testing = True
    app_reloaded.config["DISABLE_TLS_ENFORCEMENT"] = True
    client_reloaded = app_reloaded.test_client()

    still_locked = client_reloaded.post(
        "/login",
        data={"username": "agent01", "password": "MetroOpsPass!01"},
        follow_redirects=False,
    )
    assert still_locked.status_code == 302
    assert "/login" in (still_locked.headers.get("Location") or "")


def test_pricing_deterministic_edge_rounding_and_discount(tmp_path):
    client, app = build_client(tmp_path)
    login_agent(client)

    with app.app_context():
        db = app.get_db()
        dep_id = db.execute("SELECT id FROM departures ORDER BY id LIMIT 1").fetchone()[
            0
        ]
        departure_time = (datetime.now(UTC) + timedelta(hours=6)).isoformat()
        db.execute(
            "UPDATE departures SET departure_time=?, base_price=? WHERE id=?",
            (departure_time, 10.015, dep_id),
        )
        db.execute("DELETE FROM rate_plans")
        dep_date = datetime.fromisoformat(departure_time).date().isoformat()
        db.execute(
            "INSERT INTO rate_plans (name,start_date,end_date,amount_delta) VALUES (?,?,?,?)",
            ("Discount", dep_date, dep_date, -0.02),
        )
        db.commit()

    hold = auth_post(
        client, "/api/bookings/hold", json={"departure_id": dep_id, "seats": 1}
    )
    nonce = auth_post(
        client, "/api/security/nonce", data={"action": "booking_confirm"}
    ).get_json()["nonce"]
    confirm = auth_post(
        client,
        "/api/bookings/confirm",
        json={
            "hold_nonce": hold.get_json()["hold_nonce"],
            "request_nonce": nonce,
            "contact": "edge@test.local",
        },
    )
    assert confirm.status_code == 200
    assert confirm.get_json()["total_price"] == 10.0
