import secrets
import json
from datetime import timedelta

from flask import flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def register_core_routes(app, ctx):
    login_required = ctx["login_required"]
    require_permission = ctx["require_permission"]
    get_db = ctx["get_db"]
    current_user = ctx["current_user"]
    utc_now = ctx["utc_now"]
    to_iso = ctx["to_iso"]
    from_iso = ctx["from_iso"]
    format_clock = ctx["format_clock"]
    log_risk = ctx["log_risk"]
    password_policy_error = ctx["password_policy_error"]
    booking_rule_values = ctx["booking_rule_values"]

    SENSITIVE_KEYS = {"password", "token", "credentials", "secret"}

    def redact_sensitive(value, key=None):
        key_lower = str(key).lower() if key is not None else None
        if key_lower in SENSITIVE_KEYS:
            return "***REDACTED***"
        if isinstance(value, dict):
            return {k: redact_sensitive(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [redact_sensitive(item) for item in value]
        return value

    def audit_admin_action(
        action,
        actor_user_id,
        organization_id=None,
        target_user_id=None,
        metadata=None,
        before_data=None,
        after_data=None,
    ):
        db = get_db()
        db.execute(
            "INSERT INTO admin_audit_log (action,actor_user_id,organization_id,target_user_id,metadata,before_data,after_data,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                action,
                actor_user_id,
                organization_id,
                target_user_id,
                json.dumps(redact_sensitive(metadata or {})),
                json.dumps(redact_sensitive(before_data or {})),
                json.dumps(redact_sensitive(after_data or {})),
                to_iso(utc_now()),
            ),
        )

    def valid_role(role):
        return role in {"employee", "supervisor", "hr", "admin"}

    @app.get("/")
    def root():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        if not user:
            flash("Invalid credentials", "error")
            return redirect(url_for("login"))

        if user["lockout_until"] and from_iso(user["lockout_until"]) > utc_now():
            flash("Account temporarily locked for 15 minutes", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            failed = user["failed_attempts"] + 1
            lockout_until = None
            if failed >= 5:
                lockout_until = to_iso(utc_now() + timedelta(minutes=15))
                log_risk("failed_login_lockout", f"username={username}", user["id"])
                failed = 0
            db.execute(
                "UPDATE users SET failed_attempts=?, lockout_until=? WHERE id=?",
                (failed, lockout_until, user["id"]),
            )
            db.commit()
            flash("Invalid credentials", "error")
            return redirect(url_for("login"))

        db.execute(
            "UPDATE users SET failed_attempts=0, lockout_until=NULL WHERE id=?",
            (user["id"],),
        )
        db.commit()
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = to_iso(utc_now())
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.post("/admin/users")
    @login_required
    @require_permission("admin:all")
    def admin_create_user():
        payload = request.get_json(force=True)
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        role = payload.get("role") or "employee"
        depot_assignment = payload.get("depot_assignment") or "Unassigned"
        if not username:
            return jsonify({"error": "Username required"}), 422
        if not valid_role(role):
            return jsonify({"error": "Invalid role"}), 422
        policy_error = password_policy_error(password)
        if policy_error:
            return jsonify({"error": policy_error}), 422
        db = get_db()
        exists = db.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if exists:
            return jsonify({"error": "Username already exists"}), 409
        db.execute(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                role,
                depot_assignment,
                to_iso(utc_now()),
            ),
        )
        created_id = db.execute(
            "SELECT id FROM users WHERE username=?", (username,)
        ).fetchone()["id"]
        audit_admin_action(
            "user_provisioned",
            session["user_id"],
            target_user_id=created_id,
            metadata={"username": username},
            before_data={},
            after_data={"role": role, "depot_assignment": depot_assignment},
        )
        db.commit()
        return jsonify({"ok": True}), 201

    @app.post("/admin/organizations")
    @login_required
    @require_permission("admin:all")
    def admin_create_organization():
        payload = request.get_json(force=True)
        name = (payload.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Organization name required"}), 422
        db = get_db()
        exists = db.execute(
            "SELECT id FROM organizations WHERE name=?", (name,)
        ).fetchone()
        if exists:
            return jsonify({"error": "Organization already exists"}), 409
        cursor = db.execute(
            "INSERT INTO organizations (name,created_by,created_at) VALUES (?,?,?)",
            (name, session["user_id"], to_iso(utc_now())),
        )
        org_id = cursor.lastrowid
        audit_admin_action(
            "organization_created",
            session["user_id"],
            organization_id=org_id,
            metadata={"name": name},
            before_data={},
            after_data={"name": name},
        )
        db.commit()
        return jsonify({"ok": True, "organization_id": org_id}), 201

    @app.post("/admin/organizations/<int:organization_id>/users")
    @login_required
    @require_permission("admin:all")
    def admin_provision_user(organization_id):
        payload = request.get_json(force=True)
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        role = payload.get("role") or "employee"
        if not username:
            return jsonify({"error": "Username required"}), 422
        if not valid_role(role):
            return jsonify({"error": "Invalid role"}), 422
        policy_error = password_policy_error(password)
        if policy_error:
            return jsonify({"error": policy_error}), 422

        db = get_db()
        org = db.execute(
            "SELECT id,name FROM organizations WHERE id=?", (organization_id,)
        ).fetchone()
        if not org:
            return jsonify({"error": "Organization not found"}), 404
        exists = db.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if exists:
            return jsonify({"error": "Username already exists"}), 409

        cursor = db.execute(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                role,
                org["name"],
                to_iso(utc_now()),
            ),
        )
        user_id = cursor.lastrowid
        db.execute(
            "INSERT INTO organization_role_assignments (organization_id,user_id,role,status,assigned_by,assigned_at) VALUES (?,?,?,?,?,?)",
            (
                organization_id,
                user_id,
                role,
                "active",
                session["user_id"],
                to_iso(utc_now()),
            ),
        )
        audit_admin_action(
            "organization_user_provisioned",
            session["user_id"],
            organization_id=organization_id,
            target_user_id=user_id,
            metadata={"username": username},
            before_data={},
            after_data={"role": role, "organization": org["name"]},
        )
        db.commit()
        return jsonify({"ok": True, "user_id": user_id}), 201

    @app.post("/admin/organizations/<int:organization_id>/roles/assign")
    @login_required
    @require_permission("admin:all")
    def admin_assign_role(organization_id):
        payload = request.get_json(force=True)
        try:
            target_user_id = int(payload.get("user_id"))
        except (TypeError, ValueError):
            return jsonify({"error": "user_id is required"}), 422
        role = payload.get("role") or "employee"
        if not valid_role(role):
            return jsonify({"error": "Invalid role"}), 422

        db = get_db()
        org = db.execute(
            "SELECT id,name FROM organizations WHERE id=?", (organization_id,)
        ).fetchone()
        if not org:
            return jsonify({"error": "Organization not found"}), 404
        user = db.execute(
            "SELECT id,depot_assignment FROM users WHERE id=?", (target_user_id,)
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user["depot_assignment"] != org["name"]:
            return jsonify(
                {"error": "Cross-organization role assignment is not allowed"}
            ), 422

        assignment = db.execute(
            "SELECT id,role,status FROM organization_role_assignments WHERE organization_id=? AND user_id=?",
            (organization_id, target_user_id),
        ).fetchone()
        before = dict(assignment) if assignment else {}
        if assignment:
            db.execute(
                "UPDATE organization_role_assignments SET role=?, status='active', assigned_by=?, assigned_at=?, revoked_by=NULL, revoked_at=NULL WHERE id=?",
                (role, session["user_id"], to_iso(utc_now()), assignment["id"]),
            )
        else:
            db.execute(
                "INSERT INTO organization_role_assignments (organization_id,user_id,role,status,assigned_by,assigned_at) VALUES (?,?,?,?,?,?)",
                (
                    organization_id,
                    target_user_id,
                    role,
                    "active",
                    session["user_id"],
                    to_iso(utc_now()),
                ),
            )
        db.execute("UPDATE users SET role=? WHERE id=?", (role, target_user_id))
        audit_admin_action(
            "role_assigned",
            session["user_id"],
            organization_id=organization_id,
            target_user_id=target_user_id,
            metadata={
                "token": payload.get("token"),
                "credentials": payload.get("credentials"),
                "metadata": payload.get("metadata"),
            },
            before_data={
                "assignment": before,
                "request_before": payload.get("before_data"),
            },
            after_data={
                "assignment": {"role": role, "status": "active"},
                "request_after": payload.get("after_data"),
            },
        )
        db.commit()
        return jsonify({"ok": True}), 200

    @app.post("/admin/organizations/<int:organization_id>/roles/revoke")
    @login_required
    @require_permission("admin:all")
    def admin_revoke_role(organization_id):
        payload = request.get_json(force=True)
        try:
            target_user_id = int(payload.get("user_id"))
        except (TypeError, ValueError):
            return jsonify({"error": "user_id is required"}), 422

        db = get_db()
        org = db.execute(
            "SELECT id,name FROM organizations WHERE id=?", (organization_id,)
        ).fetchone()
        if not org:
            return jsonify({"error": "Organization not found"}), 404
        user = db.execute(
            "SELECT id,depot_assignment FROM users WHERE id=?", (target_user_id,)
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user["depot_assignment"] != org["name"]:
            return jsonify(
                {"error": "Cross-organization role revoke is not allowed"}
            ), 422

        assignment = db.execute(
            "SELECT id,role,status FROM organization_role_assignments WHERE organization_id=? AND user_id=?",
            (organization_id, target_user_id),
        ).fetchone()
        if not assignment:
            return jsonify({"error": "Role assignment not found"}), 404
        before = dict(assignment)
        db.execute(
            "UPDATE organization_role_assignments SET status='revoked', revoked_by=?, revoked_at=? WHERE id=?",
            (session["user_id"], to_iso(utc_now()), assignment["id"]),
        )
        audit_admin_action(
            "role_revoked",
            session["user_id"],
            organization_id=organization_id,
            target_user_id=target_user_id,
            metadata={
                "password": payload.get("password"),
                "metadata": payload.get("metadata"),
            },
            before_data={
                "assignment": before,
                "request_before": payload.get("before_data"),
            },
            after_data={
                "assignment": {"role": assignment["role"], "status": "revoked"},
                "request_after": payload.get("after_data"),
            },
        )
        db.commit()
        return jsonify({"ok": True}), 200

    @app.get("/api/config/booking-rules")
    @login_required
    @require_permission("config:manage")
    def get_booking_rules_config():
        return jsonify(booking_rule_values(get_db()))

    @app.post("/api/config/booking-rules")
    @login_required
    @require_permission("config:manage")
    def update_booking_rules_config():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error": "Invalid JSON payload"}), 400

        allowed_keys = {
            "booking_min_advance_hours": (1, 168),
            "booking_max_horizon_days": (1, 365),
            "commuter_bundle_min_days": (1, 30),
            "seat_hold_timeout_minutes": (1, 120),
        }

        db = get_db()
        now_iso = to_iso(utc_now())
        changed = 0
        for key, (min_v, max_v) in allowed_keys.items():
            if key not in payload:
                continue
            try:
                new_value = int(payload[key])
            except (TypeError, ValueError):
                return jsonify({"error": f"Invalid integer for {key}"}), 422
            if new_value < min_v or new_value > max_v:
                return jsonify(
                    {"error": f"{key} must be between {min_v} and {max_v}"}
                ), 422

            old_row = db.execute(
                "SELECT value FROM system_config WHERE key=?", (key,)
            ).fetchone()
            old_value = old_row["value"] if old_row else None
            db.execute(
                "INSERT INTO system_config (key,value,updated_at,updated_by) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (key, str(new_value), now_iso, session["user_id"]),
            )
            db.execute(
                "INSERT INTO config_audit_log (key,old_value,new_value,changed_by,changed_at,reason) VALUES (?,?,?,?,?,?)",
                (
                    key,
                    old_value,
                    str(new_value),
                    session["user_id"],
                    now_iso,
                    "booking_rule_update",
                ),
            )
            changed += 1

        if changed == 0:
            return jsonify({"error": "No supported config keys supplied"}), 422
        db.commit()
        return jsonify({"ok": True, "rules": booking_rule_values(db)})

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        routes = get_db().execute("SELECT * FROM routes ORDER BY code").fetchall()
        departures = (
            get_db()
            .execute(
                "SELECT d.id, r.code, d.departure_time FROM departures d JOIN routes r ON r.id=d.route_id ORDER BY d.departure_time LIMIT 10"
            )
            .fetchall()
        )
        return render_template(
            "dashboard.html", user=user, routes=routes, departures=departures
        )

    @app.get("/reports")
    @login_required
    @require_permission("reports:view")
    def reports_index():
        db = get_db()
        now = utc_now()
        since = to_iso(now - timedelta(days=7))
        risk_rows = db.execute(
            """
            SELECT event_type, COUNT(*) AS total
            FROM risk_events
            WHERE created_at >= ?
            GROUP BY event_type
            ORDER BY total DESC
            """,
            (since,),
        ).fetchall()
        login_lockouts = db.execute(
            "SELECT COUNT(*) FROM risk_events WHERE event_type='failed_login_lockout' AND created_at >= ?",
            (since,),
        ).fetchone()[0]
        refresh_limits = db.execute(
            "SELECT COUNT(*) FROM risk_events WHERE event_type='excessive_refresh' AND created_at >= ?",
            (since,),
        ).fetchone()[0]
        speed_anomalies = db.execute(
            "SELECT COUNT(*) FROM risk_events WHERE event_type='impossible_speed_jump' AND created_at >= ?",
            (since,),
        ).fetchone()[0]
        return render_template(
            "reports.html",
            risk_rows=risk_rows,
            login_lockouts=login_lockouts,
            refresh_limits=refresh_limits,
            speed_anomalies=speed_anomalies,
            generated_at=format_clock(now),
        )

    @app.get("/kiosk")
    def kiosk():
        routes = get_db().execute("SELECT * FROM routes ORDER BY code").fetchall()
        hold_timeout_minutes = booking_rule_values(get_db())[
            "seat_hold_timeout_minutes"
        ]
        return render_template(
            "kiosk.html", routes=routes, hold_timeout_minutes=hold_timeout_minutes
        )
