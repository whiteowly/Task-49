import secrets
import re
from datetime import timedelta

from flask import jsonify, redirect, request, session, url_for


def register_security_guards(app, deps):
    utc_now = deps["utc_now"]
    from_iso = deps["from_iso"]
    to_iso = deps["to_iso"]
    get_db = deps["get_db"]
    log_risk = deps["log_risk"]
    cleanup_expired_holds = deps["cleanup_expired_holds"]

    endpoint_screen_map = {
        "arrival_board": "arrival-board",
        "route_distribution": "route-distribution",
        "seat_availability_partial": "seat-availability-partial",
        "seat_availability_query": "seat-availability-query",
        "search_departures": "departures-search",
    }

    def validated_heartbeat_screen():
        raw = (request.args.get("screen") or "").strip().lower()
        if not raw:
            return "default"
        if len(raw) > 80:
            return "invalid"
        if not re.fullmatch(r"[a-z0-9._:/-]+", raw):
            return "invalid"
        return raw

    def canonical_refresh_screen():
        endpoint = request.endpoint or "unknown"
        if endpoint == "heartbeat":
            return f"heartbeat:{validated_heartbeat_screen()}"
        if endpoint == "arrival_board":
            route_id = request.args.get("route_id", type=int)
            return f"arrival-board:route:{route_id if route_id is not None else 'all'}"
        if endpoint == "seat_availability_query":
            departure_id = request.args.get("departure_id", type=int)
            return f"seat-availability-query:departure:{departure_id if departure_id is not None else 'none'}"
        if endpoint == "seat_availability_partial":
            departure_id = (
                request.view_args.get("departure_id") if request.view_args else None
            )
            return f"seat-availability-partial:departure:{departure_id if departure_id is not None else 'none'}"
        if endpoint in endpoint_screen_map:
            return endpoint_screen_map[endpoint]
        path = (request.path or "unknown").strip("/").replace("/", "-")
        return f"path:{path or 'root'}"

    @app.before_request
    def security_guards():
        if (
            app.config["TLS_REQUIRED"]
            and not app.config["DISABLE_TLS_ENFORCEMENT"]
            and not app.testing
            and request.endpoint != "static"
        ):
            secure = (
                request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
            )
            if not secure:
                return jsonify({"error": "TLS is required"}), 426

        if (
            app.config.get("CSRF_PROTECT", True)
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and session.get("user_id")
            and request.endpoint not in {"login", "static", "gateway_vehicle_pings"}
        ):
            header_token = request.headers.get("X-CSRF-Token", "")
            form_token = request.form.get("csrf_token", "")
            token = header_token or form_token
            if token != session.get("csrf_token"):
                return jsonify({"error": "Invalid CSRF token"}), 403

        if session.get("user_id"):
            now = utc_now()
            last_seen = session.get("last_seen")
            if last_seen:
                idle = now - from_iso(last_seen)
                if idle > timedelta(minutes=30):
                    session.clear()
                    return redirect(url_for("login"))
            session["last_seen"] = to_iso(now)

        refresh_endpoints = {
            "heartbeat",
            "arrival_board",
            "route_distribution",
            "seat_availability_partial",
            "seat_availability_query",
            "search_departures",
        }
        if request.endpoint in refresh_endpoints:
            now = utc_now()
            db = get_db()
            screen = canonical_refresh_screen()
            actor_key = (
                f"user:{session['user_id']}"
                if session.get("user_id")
                else f"anon:{session.setdefault('anon_refresh_id', secrets.token_hex(12))}"
            )

            rolling = None
            if session.get("user_id"):
                user_id = session["user_id"]
                bucket = now.strftime("%Y-%m-%dT%H:%M")
                previous_bucket = (now - timedelta(minutes=1)).strftime(
                    "%Y-%m-%dT%H:%M"
                )
                row = db.execute(
                    "SELECT attempt_count FROM refresh_attempts WHERE user_id=? AND screen=? AND minute_bucket=?",
                    (user_id, screen, bucket),
                ).fetchone()
                count = (row["attempt_count"] if row else 0) + 1
                if row:
                    db.execute(
                        "UPDATE refresh_attempts SET attempt_count=? WHERE user_id=? AND screen=? AND minute_bucket=?",
                        (count, user_id, screen, bucket),
                    )
                else:
                    db.execute(
                        "INSERT INTO refresh_attempts (user_id,screen,minute_bucket,attempt_count) VALUES (?,?,?,?)",
                        (user_id, screen, bucket, count),
                    )

                rolling = db.execute(
                    "SELECT COALESCE(SUM(attempt_count),0) FROM refresh_attempts WHERE user_id=? AND screen=? AND minute_bucket IN (?,?)",
                    (user_id, screen, bucket, previous_bucket),
                ).fetchone()[0]

            cadence = db.execute(
                "SELECT last_seen FROM refresh_cadence WHERE actor_key=? AND screen=?",
                (actor_key, screen),
            ).fetchone()
            cadence_blocked = cadence and (
                now - from_iso(cadence["last_seen"])
            ) < timedelta(seconds=10)

            if not cadence_blocked:
                db.execute(
                    "INSERT INTO refresh_cadence (actor_key,screen,last_seen) VALUES (?,?,?) ON CONFLICT(actor_key,screen) DO UPDATE SET last_seen=excluded.last_seen",
                    (actor_key, screen, to_iso(now)),
                )

            if session.get("user_id") and rolling is not None and rolling > 30:
                log_risk(
                    "excessive_refresh",
                    f"screen={screen}, count_60s={rolling}",
                    session["user_id"],
                )

            if cadence_blocked:
                retry_after = max(
                    1, 10 - int((now - from_iso(cadence["last_seen"])).total_seconds())
                )
                cleanup_expired_holds(db)
                db.commit()
                return jsonify(
                    {
                        "error": "Refresh allowed once every 10 seconds",
                        "retry_after_seconds": retry_after,
                    }
                ), 429

            if session.get("user_id") and rolling is not None and rolling > 30:
                cleanup_expired_holds(db)
                db.commit()
                return jsonify(
                    {"error": "Refresh rate exceeded", "retry_after_seconds": 10}
                ), 429

            db = get_db()
            cleanup_expired_holds(db)
            db.commit()

    @app.after_request
    def cache_control_headers(response):
        if (
            session.get("user_id")
            and request.method == "GET"
            and response.mimetype == "text/html"
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
