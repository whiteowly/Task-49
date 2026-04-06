import sqlite3
import os
from datetime import timedelta

from werkzeug.security import generate_password_hash


def runtime_env_mode():
    raw_mode = (
        os.environ.get("METROOPS_RUNTIME_ENV")
        or os.environ.get("FLASK_ENV")
        or os.environ.get("APP_ENV")
        or "production"
    )
    mode = raw_mode.strip().lower()
    development_modes = {"development", "dev", "local", "test", "testing"}
    return mode, mode in development_modes


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('employee','supervisor','hr','admin')),
    depot_assignment TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until TEXT,
    face_identifier_encrypted BLOB,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS organization_role_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('employee','supervisor','hr','admin')),
    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
    assigned_by INTEGER NOT NULL,
    assigned_at TEXT NOT NULL,
    revoked_by INTEGER,
    revoked_at TEXT,
    UNIQUE(organization_id, user_id),
    FOREIGN KEY(organization_id) REFERENCES organizations(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(assigned_by) REFERENCES users(id),
    FOREIGN KEY(revoked_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS permissions (
    role TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY(role, permission)
);
CREATE TABLE IF NOT EXISTS sessions_nonce (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    nonce TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS refresh_attempts (
    user_id INTEGER NOT NULL,
    screen TEXT NOT NULL,
    minute_bucket TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(user_id, screen, minute_bucket)
);
CREATE TABLE IF NOT EXISTS refresh_cadence (
    actor_key TEXT NOT NULL,
    screen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY(actor_key, screen)
);
CREATE TABLE IF NOT EXISTS abuse_attempts (
    actor_key TEXT NOT NULL,
    action TEXT NOT NULL,
    minute_bucket TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(actor_key, action, minute_bucket)
);
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by INTEGER
);
CREATE TABLE IF NOT EXISTS config_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT NOT NULL,
    changed_by INTEGER NOT NULL,
    changed_at TEXT NOT NULL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    actor_user_id INTEGER NOT NULL,
    organization_id INTEGER,
    target_user_id INTEGER,
    metadata TEXT,
    before_data TEXT,
    after_data TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(actor_user_id) REFERENCES users(id),
    FOREIGN KEY(organization_id) REFERENCES organizations(id),
    FOREIGN KEY(target_user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    origin TEXT NOT NULL,
    destination TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS departures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id INTEGER NOT NULL,
    departure_time TEXT NOT NULL,
    base_price REAL NOT NULL,
    total_seats INTEGER NOT NULL,
    FOREIGN KEY(route_id) REFERENCES routes(id)
);
CREATE TABLE IF NOT EXISTS rate_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    amount_delta REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS seat_holds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    departure_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    seats INTEGER NOT NULL,
    kiosk_session_id TEXT,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','expired','converted','cancelled')),
    nonce TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(departure_id) REFERENCES departures(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    departure_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    seats INTEGER NOT NULL,
    total_price REAL NOT NULL,
    status TEXT NOT NULL,
    kiosk_session_id TEXT,
    bundle_days INTEGER,
    contact_encrypted BLOB,
    nonce_used TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(departure_id) REFERENCES departures(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id INTEGER NOT NULL,
    stop_name TEXT NOT NULL,
    stop_sequence INTEGER NOT NULL,
    scheduled_arrival TEXT NOT NULL,
    FOREIGN KEY(route_id) REFERENCES routes(id)
);
CREATE TABLE IF NOT EXISTS vehicle_pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id TEXT NOT NULL,
    route_id INTEGER NOT NULL,
    stop_sequence INTEGER NOT NULL,
    lat REAL,
    lon REAL,
    speed_mph REAL NOT NULL,
    ping_time TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(route_id) REFERENCES routes(id)
);
CREATE TABLE IF NOT EXISTS warehouses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    warehouse_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
);
CREATE TABLE IF NOT EXISTS bins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    bin_type TEXT NOT NULL,
    capacity_cuft REAL NOT NULL,
    capacity_lb REAL NOT NULL,
    current_cuft REAL NOT NULL DEFAULT 0,
    current_lb REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'available',
    frozen INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(zone_id) REFERENCES zones(id)
);
CREATE TABLE IF NOT EXISTS depot_bin_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('bin_type','bin_status')),
    rule_value TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    UNIQUE(rule_type, rule_value)
);
CREATE TABLE IF NOT EXISTS inventory_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id INTEGER NOT NULL,
    item_name TEXT NOT NULL,
    volume_cuft REAL NOT NULL,
    weight_lb REAL NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(bin_id) REFERENCES bins(id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content_md TEXT NOT NULL,
    note_type TEXT NOT NULL CHECK(note_type IN ('incident','training')),
    owner_id INTEGER NOT NULL,
    depot_scope TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(owner_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS note_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    version_no INTEGER NOT NULL,
    title TEXT NOT NULL,
    content_md TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(note_id) REFERENCES notes(id)
);
CREATE TABLE IF NOT EXISTS note_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_note_id INTEGER NOT NULL,
    to_note_id INTEGER NOT NULL,
    link_type TEXT NOT NULL,
    UNIQUE(from_note_id, to_note_id, link_type),
    FOREIGN KEY(from_note_id) REFERENCES notes(id),
    FOREIGN KEY(to_note_id) REFERENCES notes(id)
);
CREATE TABLE IF NOT EXISTS note_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    uploaded_by INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY(note_id) REFERENCES notes(id)
);
CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a INTEGER NOT NULL,
    user_b INTEGER NOT NULL,
    relation TEXT NOT NULL CHECK(relation IN ('follow','block','report','favorite','like')),
    created_at TEXT NOT NULL,
    UNIQUE(user_a, user_b, relation),
    FOREIGN KEY(user_a) REFERENCES users(id),
    FOREIGN KEY(user_b) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    widget_key TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    label_a TEXT NOT NULL DEFAULT 'Version A',
    label_b TEXT NOT NULL DEFAULT 'Version B',
    split_a_percent INTEGER NOT NULL DEFAULT 50 CHECK(split_a_percent >= 0 AND split_a_percent <= 100)
);
CREATE TABLE IF NOT EXISTS experiment_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    variant TEXT NOT NULL CHECK(variant IN ('A','B')),
    created_at TEXT NOT NULL,
    UNIQUE(experiment_id, user_id),
    FOREIGN KEY(experiment_id) REFERENCES experiments(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS experiment_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by INTEGER NOT NULL,
    changed_at TEXT NOT NULL,
    FOREIGN KEY(experiment_id) REFERENCES experiments(id),
    FOREIGN KEY(changed_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    widget_key TEXT,
    variant TEXT,
    created_at TEXT NOT NULL,
    metadata TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS ranking_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    relevant INTEGER NOT NULL,
    recommended INTEGER NOT NULL,
    ndcg REAL NOT NULL,
    covered INTEGER NOT NULL,
    diverse INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _ensure_migrations(db):
    user_cols = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "failed_attempts" not in user_cols:
        db.execute(
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"
        )
    if "lockout_until" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN lockout_until TEXT")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS refresh_cadence (
            actor_key TEXT NOT NULL,
            screen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY(actor_key, screen)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS abuse_attempts (
            actor_key TEXT NOT NULL,
            action TEXT NOT NULL,
            minute_bucket TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(actor_key, action, minute_bucket)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by INTEGER
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS config_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT NOT NULL,
            changed_by INTEGER NOT NULL,
            changed_at TEXT NOT NULL,
            reason TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS organization_role_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('employee','supervisor','hr','admin')),
            status TEXT NOT NULL CHECK(status IN ('active','revoked')),
            assigned_by INTEGER NOT NULL,
            assigned_at TEXT NOT NULL,
            revoked_by INTEGER,
            revoked_at TEXT,
            UNIQUE(organization_id, user_id),
            FOREIGN KEY(organization_id) REFERENCES organizations(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id),
            FOREIGN KEY(revoked_by) REFERENCES users(id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            actor_user_id INTEGER NOT NULL,
            organization_id INTEGER,
            target_user_id INTEGER,
            metadata TEXT,
            before_data TEXT,
            after_data TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id),
            FOREIGN KEY(organization_id) REFERENCES organizations(id),
            FOREIGN KEY(target_user_id) REFERENCES users(id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS experiment_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            experiment_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            changed_by INTEGER NOT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY(experiment_id) REFERENCES experiments(id),
            FOREIGN KEY(changed_by) REFERENCES users(id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS depot_bin_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL CHECK(rule_type IN ('bin_type','bin_status')),
            rule_value TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(rule_type, rule_value)
        )
        """
    )
    note_cols = {row[1] for row in db.execute("PRAGMA table_info(notes)").fetchall()}
    if "depot_scope" not in note_cols:
        db.execute("ALTER TABLE notes ADD COLUMN depot_scope TEXT")
    db.execute(
        """
        UPDATE notes
        SET depot_scope=(
            SELECT depot_assignment FROM users u WHERE u.id = notes.owner_id
        )
        WHERE depot_scope IS NULL
        """
    )
    experiment_cols = {
        row[1] for row in db.execute("PRAGMA table_info(experiments)").fetchall()
    }
    if "split_a_percent" not in experiment_cols:
        db.execute(
            "ALTER TABLE experiments ADD COLUMN split_a_percent INTEGER NOT NULL DEFAULT 50"
        )
    db.execute(
        "UPDATE experiments SET split_a_percent=50 WHERE split_a_percent IS NULL"
    )
    seat_hold_cols = {
        row[1] for row in db.execute("PRAGMA table_info(seat_holds)").fetchall()
    }
    if "kiosk_session_id" not in seat_hold_cols:
        db.execute("ALTER TABLE seat_holds ADD COLUMN kiosk_session_id TEXT")
    booking_cols = {
        row[1] for row in db.execute("PRAGMA table_info(bookings)").fetchall()
    }
    if "kiosk_session_id" not in booking_cols:
        db.execute("ALTER TABLE bookings ADD COLUMN kiosk_session_id TEXT")
    default_rules = [
        ("bin_type", "standard"),
        ("bin_type", "cold"),
        ("bin_type", "hazmat"),
        ("bin_type", "secure"),
        ("bin_status", "available"),
        ("bin_status", "unavailable"),
        ("bin_status", "maintenance"),
    ]
    db.executemany(
        "INSERT OR IGNORE INTO depot_bin_rules (rule_type,rule_value,is_active) VALUES (?,?,1)",
        default_rules,
    )

    default_config = [
        ("booking_min_advance_hours", "2"),
        ("booking_max_horizon_days", "30"),
        ("commuter_bundle_min_days", "3"),
        ("seat_hold_timeout_minutes", "8"),
    ]
    db.executemany(
        "INSERT OR IGNORE INTO system_config (key,value,updated_at,updated_by) VALUES (?,?,datetime('now'),NULL)",
        default_config,
    )


def initialize_database(db_path, utc_now, to_iso):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA_SQL)
    _ensure_migrations(db)
    runtime_env, development_mode = runtime_env_mode()

    permissions = {
        "employee": ["notes:read", "notes:write", "booking:create", "social:use"],
        "supervisor": [
            "notes:read",
            "notes:write",
            "booking:create",
            "social:use",
            "ops:ingest",
            "experiments:manage",
            "analytics:view",
            "depot:manage",
            "config:manage",
        ],
        "hr": ["notes:read", "notes:write", "reports:view"],
        "admin": [
            "notes:read",
            "notes:write",
            "booking:create",
            "social:use",
            "ops:ingest",
            "experiments:manage",
            "analytics:view",
            "depot:manage",
            "config:manage",
            "admin:all",
        ],
    }

    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        now_iso = to_iso(utc_now())
        if development_mode:
            users = [
                (
                    "agent01",
                    generate_password_hash("MetroOpsPass!01"),
                    "employee",
                    "Main Depot",
                ),
                (
                    "supervisor01",
                    generate_password_hash("MetroOpsPass!02"),
                    "supervisor",
                    "Main Depot",
                ),
                ("hr01", generate_password_hash("MetroOpsPass!03"), "hr", "HQ"),
                ("admin01", generate_password_hash("MetroOpsPass!04"), "admin", "HQ"),
            ]
            bootstrap_profile = "dev_defaults_v1"
        else:
            admin_username = (
                os.environ.get("METROOPS_BOOTSTRAP_ADMIN_USERNAME") or "admin"
            ).strip()
            admin_password = os.environ.get("METROOPS_BOOTSTRAP_ADMIN_PASSWORD") or ""
            if len(admin_password) < 12:
                raise RuntimeError(
                    "Non-development bootstrap requires METROOPS_BOOTSTRAP_ADMIN_PASSWORD with at least 12 characters"
                )
            users = [
                (admin_username, generate_password_hash(admin_password), "admin", "HQ"),
            ]
            bootstrap_profile = "secure_bootstrap_v1"
        db.executemany(
            "INSERT INTO users (username,password_hash,role,depot_assignment,created_at) VALUES (?,?,?,?,?)",
            [(u, p, r, d, now_iso) for (u, p, r, d) in users],
        )
        db.execute(
            "INSERT INTO system_config (key,value,updated_at,updated_by) VALUES (?,?,datetime('now'),NULL) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=NULL",
            ("bootstrap_profile", bootstrap_profile),
        )

        db.execute(
            "INSERT INTO routes (code,origin,destination) VALUES ('R-101','Central','North Yard')"
        )
        db.execute(
            "INSERT INTO routes (code,origin,destination) VALUES ('R-202','Central','West Loop')"
        )
        route_ids = [
            r[0] for r in db.execute("SELECT id FROM routes ORDER BY id").fetchall()
        ]
        now = utc_now()
        for idx, route_id in enumerate(route_ids):
            for hop in range(1, 5):
                departure = now + timedelta(hours=idx + hop)
                db.execute(
                    "INSERT INTO departures (route_id,departure_time,base_price,total_seats) VALUES (?,?,?,?)",
                    (route_id, to_iso(departure), 20 + idx * 5, 30),
                )
            for stop_seq in range(1, 5):
                scheduled = now + timedelta(minutes=stop_seq * (idx + 12))
                db.execute(
                    "INSERT INTO schedules (route_id,stop_name,stop_sequence,scheduled_arrival) VALUES (?,?,?,?)",
                    (route_id, f"Stop {stop_seq}", stop_seq, to_iso(scheduled)),
                )

        db.execute(
            "INSERT INTO rate_plans (name,start_date,end_date,amount_delta) VALUES ('Peak Surcharge','2026-01-01','2026-12-31',4.5)"
        )
        db.execute("INSERT INTO warehouses (name) VALUES ('Main Depot')")
        warehouse_id = db.execute(
            "SELECT id FROM warehouses WHERE name='Main Depot'"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO zones (warehouse_id,name) VALUES (?,?)",
            (warehouse_id, "Zone A"),
        )
        zone_id = db.execute("SELECT id FROM zones WHERE name='Zone A'").fetchone()[0]
        db.execute(
            "INSERT INTO bins (zone_id,code,bin_type,capacity_cuft,capacity_lb,status) VALUES (?,?,?,?,?,?)",
            (zone_id, "A-01", "standard", 500, 4000, "available"),
        )
        db.execute(
            "INSERT INTO experiments (widget_key,enabled,label_a,label_b,split_a_percent) VALUES ('suggested-times',1,'Version A','Version B',50)"
        )

    for role, perms in permissions.items():
        db.executemany(
            "INSERT OR IGNORE INTO permissions (role, permission) VALUES (?,?)",
            [(role, p) for p in perms],
        )
    if not development_mode:
        profile = db.execute(
            "SELECT value FROM system_config WHERE key='bootstrap_profile'"
        ).fetchone()
        if profile and profile["value"] == "dev_defaults_v1":
            raise RuntimeError(
                "Development default credentials detected in non-development runtime. Reinitialize DB with secure bootstrap credentials."
            )
        risky_usernames = {"agent01", "supervisor01", "hr01", "admin01"}
        found = {
            row[0]
            for row in db.execute(
                "SELECT username FROM users WHERE username IN ('agent01','supervisor01','hr01','admin01')"
            ).fetchall()
        }
        if found == risky_usernames:
            raise RuntimeError(
                "Default MetroOps seed users detected in non-development runtime. Replace credentials and remove default accounts."
            )
    db.commit()
    db.close()
