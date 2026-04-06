import json
import os
import secrets
import sqlite3
import html
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet
from flask import Flask, abort, g, redirect, request, session, url_for
from werkzeug.security import generate_password_hash

try:
    from .db_bootstrap import initialize_database
except ImportError:
    from db_bootstrap import initialize_database

try:
    from .routes_collab import register_collab_routes
except ImportError:
    from routes_collab import register_collab_routes

try:
    from .routes_ops import register_ops_routes
except ImportError:
    from routes_ops import register_ops_routes

try:
    from .core_routes import register_core_routes
except ImportError:
    from core_routes import register_core_routes

try:
    from .security_middleware import register_security_guards
except ImportError:
    from security_middleware import register_security_guards

try:
    from .config import resolve_tls_disable_policy, validated_gateway_token
except ImportError:
    from config import resolve_tls_disable_policy, validated_gateway_token

try:
    import markdown
except Exception:  # pragma: no cover
    markdown = None

try:
    import bleach
except Exception:  # pragma: no cover
    bleach = None


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
ATTACHMENTS_DIR = DATA_DIR / "attachments"
DB_PATH = Path(os.environ.get("METROOPS_DB_PATH", str(DATA_DIR / "metroops.db")))
KEY_PATH = Path(os.environ.get("METROOPS_KEY_PATH", str(DATA_DIR / "secret.key")))

ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)
MIN_PASSWORD_LENGTH = 12
UTC = timezone.utc


def utc_now():
    return datetime.now(UTC)


def to_iso(dt):
    return dt.astimezone(UTC).isoformat()


def from_iso(value):
    return datetime.fromisoformat(value)


def format_clock(dt):
    return dt.strftime("%I:%M %p").lstrip("0")


def load_fernet():
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
    return Fernet(KEY_PATH.read_bytes())


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    runtime_env, tls_disable = resolve_tls_disable_policy(
        os.environ.get("DISABLE_TLS_ENFORCEMENT", "0")
    )
    development_mode = runtime_env in {"development", "dev", "local", "test", "testing"}
    configured_secret = os.environ.get("FLASK_SECRET")
    if not development_mode and not configured_secret:
        raise RuntimeError(
            "FLASK_SECRET must be explicitly set in non-development runtime"
        )
    app.config["SECRET_KEY"] = configured_secret or secrets.token_hex(32)
    app.config["RUNTIME_ENV"] = runtime_env
    app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
    session_cookie_secure = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
    if tls_disable and session_cookie_secure:
        app.logger.warning(
            "SESSION_COOKIE_SECURE forced to 0 because TLS enforcement is disabled for %s runtime",
            runtime_env,
        )
        session_cookie_secure = False
    if not development_mode and not session_cookie_secure:
        raise RuntimeError(
            "SESSION_COOKIE_SECURE must be enabled in non-development runtime"
        )
    app.config["SESSION_COOKIE_SECURE"] = session_cookie_secure
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get(
        "SESSION_COOKIE_SAMESITE", "Lax"
    )
    app.config["TLS_REQUIRED"] = True
    app.config["DISABLE_TLS_ENFORCEMENT"] = tls_disable
    gateway_token, gateway_token_state = validated_gateway_token(
        os.environ.get("METROOPS_GATEWAY_TOKEN")
    )
    app.config["GATEWAY_TOKEN"] = gateway_token
    app.config["CSRF_PROTECT"] = True
    app.fernet = load_fernet()

    if not app.config["GATEWAY_TOKEN"]:
        app.logger.warning(
            "METROOPS_GATEWAY_TOKEN is %s; LAN gateway ingestion endpoint is disabled",
            gateway_token_state,
        )
    if app.config["DISABLE_TLS_ENFORCEMENT"]:
        app.logger.warning(
            "TLS enforcement disabled for %s runtime; use this only for local development/testing",
            runtime_env,
        )
    app.logger.info(
        "startup_security runtime_env=%s tls_required=%s tls_disabled=%s session_cookie_secure=%s csrf_protect=%s",
        runtime_env,
        app.config["TLS_REQUIRED"],
        app.config["DISABLE_TLS_ENFORCEMENT"],
        app.config["SESSION_COOKIE_SECURE"],
        app.config["CSRF_PROTECT"],
    )

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH, timeout=10.0)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA busy_timeout = 10000")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        initialize_database(DB_PATH, utc_now, to_iso)

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        return (
            get_db()
            .execute(
                "SELECT id,username,role,depot_assignment FROM users WHERE id=?",
                (user_id,),
            )
            .fetchone()
        )

    def user_permissions(role):
        rows = (
            get_db()
            .execute("SELECT permission FROM permissions WHERE role=?", (role,))
            .fetchall()
        )
        return {r["permission"] for r in rows}

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                app.logger.info("auth_required_redirect endpoint=%s", request.endpoint)
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapper

    def require_permission(permission):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                user = current_user()
                if not user:
                    abort(401)
                perms = user_permissions(user["role"])
                if permission not in perms and "admin:all" not in perms:
                    app.logger.warning(
                        "authz_denied user_id=%s role=%s permission=%s endpoint=%s",
                        user["id"],
                        user["role"],
                        permission,
                        request.endpoint,
                    )
                    abort(403)
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def mask_face_identifier(value):
        if not value:
            return ""
        return f"{value[:2]}***{value[-2:]}"

    def face_identifier_log_value(value):
        masked = mask_face_identifier(value)
        return masked if masked else "<masked-empty>"

    def password_policy_error(password):
        if len(password or "") < MIN_PASSWORD_LENGTH:
            return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        return None

    def ensure_csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": ensure_csrf_token()}

    def is_note_manager(user):
        return user and user["role"] in {"hr", "admin"}

    def can_view_note(user, note_row):
        if not user:
            return False
        if is_note_manager(user):
            return True
        return note_row["depot_scope"] == user["depot_assignment"]

    def can_edit_note(user, note_row):
        return bool(
            user
            and can_view_note(user, note_row)
            and (is_note_manager(user) or note_row["owner_id"] == user["id"])
        )

    def ensure_kiosk_user_id(db):
        row = db.execute("SELECT id FROM users WHERE username='kiosk_rider'").fetchone()
        if row:
            return row["id"]
        kiosk_password = "KioskModeOnly!99"
        policy_error = password_policy_error(kiosk_password)
        if policy_error:
            raise ValueError(policy_error)
        now = to_iso(utc_now())
        cursor = db.execute(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            (
                "kiosk_rider",
                generate_password_hash(kiosk_password),
                "employee",
                "Kiosk",
                now,
            ),
        )
        db.commit()
        return cursor.lastrowid

    def log_risk(event_type, details, user_id=None):
        get_db().execute(
            "INSERT INTO risk_events (user_id,event_type,details,created_at) VALUES (?,?,?,?)",
            (user_id, event_type, details[:600], to_iso(utc_now())),
        )
        get_db().commit()

    def html_from_md(text):
        source = text or ""
        if markdown is None:
            return html.escape(source).replace("javascript:", "").replace("\n", "<br>")
        rendered = markdown.markdown(source, extensions=["extra", "sane_lists"])
        if bleach is None:
            return html.escape(source).replace("javascript:", "").replace("\n", "<br>")
        safe_html = bleach.clean(
            rendered,
            tags=[
                "p",
                "br",
                "strong",
                "em",
                "ul",
                "ol",
                "li",
                "code",
                "pre",
                "blockquote",
                "a",
                "h1",
                "h2",
                "h3",
                "h4",
                "h5",
                "h6",
            ],
            attributes={"a": ["href", "title", "rel"]},
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        return safe_html.replace("javascript:", "")

    def cleanup_expired_holds(db):
        now_iso = to_iso(utc_now())
        db.execute(
            "UPDATE seat_holds SET status='expired' WHERE status='active' AND expires_at <= ?",
            (now_iso,),
        )

    def available_seats(db, departure_id):
        cleanup_expired_holds(db)
        departure = db.execute(
            "SELECT total_seats FROM departures WHERE id=?", (departure_id,)
        ).fetchone()
        if not departure:
            return 0
        held = db.execute(
            "SELECT COALESCE(SUM(seats),0) FROM seat_holds WHERE departure_id=? AND status='active'",
            (departure_id,),
        ).fetchone()[0]
        booked = db.execute(
            "SELECT COALESCE(SUM(seats),0) FROM bookings WHERE departure_id=? AND status='confirmed'",
            (departure_id,),
        ).fetchone()[0]
        return max(0, departure["total_seats"] - held - booked)

    def get_int_config(db, key, default_value, min_value=1, max_value=3650):
        row = db.execute(
            "SELECT value FROM system_config WHERE key=?", (key,)
        ).fetchone()
        raw = row["value"] if row else str(default_value)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default_value
        return max(min_value, min(max_value, value))

    def booking_rule_values(db):
        return {
            "booking_min_advance_hours": get_int_config(
                db, "booking_min_advance_hours", 2, 1, 168
            ),
            "booking_max_horizon_days": get_int_config(
                db, "booking_max_horizon_days", 30, 1, 365
            ),
            "commuter_bundle_min_days": get_int_config(
                db, "commuter_bundle_min_days", 3, 1, 30
            ),
            "seat_hold_timeout_minutes": get_int_config(
                db, "seat_hold_timeout_minutes", 8, 1, 120
            ),
        }

    def enforce_booking_window(db, departure_time):
        rules = booking_rule_values(db)
        min_hours = rules["booking_min_advance_hours"]
        max_days = rules["booking_max_horizon_days"]
        now = utc_now()
        if departure_time < now + timedelta(hours=min_hours):
            return (
                False,
                f"Booking must be made at least {min_hours} hours before departure",
            )
        if departure_time > now + timedelta(days=max_days):
            return False, f"Booking cannot be made more than {max_days} days in advance"
        return True, "ok"

    def price_for_departure(db, departure, seats):
        base = Decimal(str(departure["base_price"]))
        dep_date = from_iso(departure["departure_time"]).date().isoformat()
        plan = db.execute(
            "SELECT amount_delta FROM rate_plans WHERE start_date <= ? AND end_date >= ? ORDER BY id DESC LIMIT 1",
            (dep_date, dep_date),
        ).fetchone()
        delta = Decimal(str(plan["amount_delta"] if plan else 0))
        total = (base + delta) * Decimal(seats)
        return float(total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    def create_booking_hold_for_user(user_id, payload):
        try:
            departure_id = int(payload.get("departure_id"))
            seats_requested = int(payload.get("seats", 1))
            bundle_days = int(payload.get("bundle_days", 1))
        except (TypeError, ValueError):
            return None, {"error": "Invalid departure_id/seats/bundle_days"}, 422
        product_type = payload.get("product_type", "single")
        kiosk_session_id = payload.get("kiosk_session_id")
        if kiosk_session_id:
            kiosk_session_id = str(kiosk_session_id).strip()[:64]
        else:
            kiosk_session_id = None

        db = get_db()
        db.execute("BEGIN EXCLUSIVE")
        try:
            departure = db.execute(
                "SELECT * FROM departures WHERE id=?", (departure_id,)
            ).fetchone()
            if not departure:
                db.rollback()
                return None, {"error": "Invalid departure"}, 404

            rules = booking_rule_values(db)
            valid, message = enforce_booking_window(
                db, from_iso(departure["departure_time"])
            )
            if not valid:
                db.rollback()
                return None, {"error": message}, 422

            min_bundle_days = rules["commuter_bundle_min_days"]
            if product_type == "commuter_bundle" and bundle_days < min_bundle_days:
                db.rollback()
                return (
                    None,
                    {
                        "error": f"Commuter bundle requires minimum {min_bundle_days} days"
                    },
                    422,
                )

            seats = available_seats(db, departure_id)
            if seats_requested <= 0 or seats_requested > seats:
                db.rollback()
                app.logger.info(
                    "booking_hold_conflict user_id=%s departure_id=%s requested=%s available=%s",
                    user_id,
                    departure_id,
                    seats_requested,
                    seats,
                )
                return (
                    None,
                    {"error": "Insufficient seats", "seats_remaining": seats},
                    409,
                )

            hold_nonce = secrets.token_urlsafe(16)
            expires_at = to_iso(
                utc_now() + timedelta(minutes=rules["seat_hold_timeout_minutes"])
            )
            db.execute(
                "INSERT INTO seat_holds (departure_id,user_id,seats,kiosk_session_id,expires_at,status,nonce,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    departure_id,
                    user_id,
                    seats_requested,
                    kiosk_session_id,
                    expires_at,
                    "active",
                    hold_nonce,
                    to_iso(utc_now()),
                ),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

        return (
            {
                "hold_nonce": hold_nonce,
                "expires_at": expires_at,
                "seats_remaining": available_seats(get_db(), departure_id),
                "kiosk_session_id": kiosk_session_id,
            },
            None,
            200,
        )

    def confirm_booking_for_user(user_id, hold_nonce, request_nonce, contact):
        ok, msg = assert_nonce(user_id, "booking_confirm", request_nonce)
        if not ok:
            log_risk("booking_nonce_failure", msg, user_id)
            return None, {"error": msg}, 409

        db = get_db()
        db.execute("BEGIN EXCLUSIVE")
        try:
            cleanup_expired_holds(db)
            hold = db.execute(
                "SELECT * FROM seat_holds WHERE nonce=? AND user_id=? AND status='active'",
                (hold_nonce, user_id),
            ).fetchone()
            if not hold:
                db.rollback()
                return None, {"error": "Hold expired or invalid"}, 410

            departure = db.execute(
                "SELECT * FROM departures WHERE id=?", (hold["departure_id"],)
            ).fetchone()
            if available_seats(db, hold["departure_id"]) < hold["seats"]:
                db.rollback()
                return None, {"error": "Inventory conflict"}, 409

            total = price_for_departure(db, departure, hold["seats"])
            encrypted_contact = (
                app.fernet.encrypt(contact.encode("utf-8")) if contact else None
            )
            db.execute(
                "INSERT INTO bookings (departure_id,user_id,seats,total_price,status,kiosk_session_id,contact_encrypted,nonce_used,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    hold["departure_id"],
                    user_id,
                    hold["seats"],
                    total,
                    "confirmed",
                    hold["kiosk_session_id"],
                    encrypted_contact,
                    request_nonce,
                    to_iso(utc_now()),
                ),
            )
            db.execute(
                "UPDATE seat_holds SET status='converted' WHERE id=?", (hold["id"],)
            )
            db.execute(
                "INSERT INTO analytics_events (user_id,event_type,created_at,metadata) VALUES (?,?,?,?)",
                (
                    user_id,
                    "booking_confirmed",
                    to_iso(utc_now()),
                    json.dumps(
                        {
                            "departure_id": hold["departure_id"],
                            "kiosk_session_id": hold["kiosk_session_id"],
                        }
                    ),
                ),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return (
            {
                "ok": True,
                "total_price": total,
                "kiosk_session_id": hold["kiosk_session_id"],
            },
            None,
            200,
        )

    def assert_nonce(user_id, action, nonce):
        row = (
            get_db()
            .execute(
                "SELECT id,expires_at,used_at FROM sessions_nonce WHERE user_id=? AND action=? AND nonce=?",
                (user_id, action, nonce),
            )
            .fetchone()
        )
        if not row:
            return False, "Invalid nonce"
        if row["used_at"]:
            return False, "Nonce already used"
        if from_iso(row["expires_at"]) < utc_now():
            return False, "Nonce expired"
        get_db().execute(
            "UPDATE sessions_nonce SET used_at=? WHERE id=?",
            (to_iso(utc_now()), row["id"]),
        )
        get_db().commit()
        return True, "ok"

    register_security_guards(
        app,
        {
            "utc_now": utc_now,
            "from_iso": from_iso,
            "to_iso": to_iso,
            "get_db": get_db,
            "log_risk": log_risk,
            "cleanup_expired_holds": cleanup_expired_holds,
        },
    )

    register_core_routes(
        app,
        {
            "login_required": login_required,
            "require_permission": require_permission,
            "get_db": get_db,
            "current_user": current_user,
            "utc_now": utc_now,
            "to_iso": to_iso,
            "from_iso": from_iso,
            "format_clock": format_clock,
            "log_risk": log_risk,
            "password_policy_error": password_policy_error,
            "booking_rule_values": booking_rule_values,
        },
    )

    register_ops_routes(
        app,
        {
            "login_required": login_required,
            "require_permission": require_permission,
            "get_db": get_db,
            "utc_now": utc_now,
            "to_iso": to_iso,
            "from_iso": from_iso,
            "format_clock": format_clock,
            "log_risk": log_risk,
            "available_seats": available_seats,
            "assert_nonce": assert_nonce,
            "create_booking_hold_for_user": create_booking_hold_for_user,
            "confirm_booking_for_user": confirm_booking_for_user,
            "ensure_kiosk_user_id": ensure_kiosk_user_id,
        },
    )

    register_collab_routes(
        app,
        {
            "current_user": current_user,
            "login_required": login_required,
            "require_permission": require_permission,
            "is_note_manager": is_note_manager,
            "can_edit_note": can_edit_note,
            "get_db": get_db,
            "utc_now": utc_now,
            "to_iso": to_iso,
            "ATTACHMENTS_DIR": ATTACHMENTS_DIR,
            "mask_face_identifier": mask_face_identifier,
            "face_identifier_log_value": face_identifier_log_value,
            "html_from_md": html_from_md,
        },
    )

    app.get_db = get_db
    app.init_db = init_db
    return app


app = create_app()
app.init_db()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    use_http = app.config.get("DISABLE_TLS_ENFORCEMENT", False) and app.config.get(
        "RUNTIME_ENV"
    ) in {
        "development",
        "dev",
        "local",
        "test",
        "testing",
    }
    if use_http:
        app.run(host="0.0.0.0", port=5000, debug=debug_mode)
    else:
        app.run(host="0.0.0.0", port=5000, debug=debug_mode, ssl_context="adhoc")
UTC = timezone.utc
