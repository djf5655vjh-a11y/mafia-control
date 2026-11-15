"""MAFIA Control - key management panel with a public /connect endpoint.

Run locally:  python app.py
Render start: gunicorn app:app --workers 1 --threads 4 --timeout 60
"""
import csv
import hashlib
import hmac
import io
import os
import platform
import random
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:  # sqlite-only local mode
    psycopg2 = None

# --------------------------------------------------------------------------- config
ADMIN_USER = os.environ.get("ADMIN_USER", "MAFIA")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "MAFIA@2026")
DB_URL = os.environ.get("DATABASE_URL", "").strip()
PG = DB_URL.startswith(("postgres://", "postgresql://")) and psycopg2 is not None
SQLITE_PATH = os.environ.get("SQLITE_PATH", "mafia.db")
STARTED = time.time()
ON_HTTPS_HOST = bool(os.environ.get("RENDER") or os.environ.get("DYNO") or os.environ.get("FLY_APP_NAME"))

SECRET = os.environ.get("SECRET_KEY") or hashlib.sha256(("mafia-control|" + ADMIN_PASS).encode()).hexdigest()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=SECRET,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_HTTPS_HOST,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    JSON_SORT_KEYS=False,
)


# --------------------------------------------------------------------------- time helpers
def now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def iso(dt):
    return dt.isoformat() if dt else None


def z(s):
    return (s + "Z") if s else None


# --------------------------------------------------------------------------- database
@contextmanager
def conn():
    if PG:
        c = psycopg2.connect(DB_URL, connect_timeout=10)
    else:
        c = sqlite3.connect(SQLITE_PATH, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def _cursor(c):
    return c.cursor(cursor_factory=RealDictCursor) if PG else c.cursor()


def run(sql, args=(), fetch="all"):
    """fetch: all | one | none (returns rowcount). Retries once on dropped Neon connections."""
    q = sql.replace("?", "%s") if PG else sql
    for attempt in (0, 1):
        try:
            with conn() as c:
                cur = _cursor(c)
                cur.execute(q, args)
                if fetch == "all":
                    return [dict(r) for r in cur.fetchall()]
                if fetch == "one":
                    r = cur.fetchone()
                    return dict(r) if r else None
                return cur.rowcount
        except Exception as e:
            if PG and attempt == 0 and isinstance(e, (psycopg2.OperationalError, psycopg2.InterfaceError)):
                continue
            raise


def run_many(statements):
    """Run several (sql, args) pairs in one transaction."""
    with conn() as c:
        cur = _cursor(c)
        for sql, args in statements:
            cur.execute(sql.replace("?", "%s") if PG else sql, args)


def init_db():
    pk = "SERIAL PRIMARY KEY" if PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    run_many([
        (f"""CREATE TABLE IF NOT EXISTS keys (
            id {pk}, key TEXT UNIQUE NOT NULL, label TEXT DEFAULT '', plan TEXT DEFAULT 'standard',
            max_devices INTEGER DEFAULT 1, created_at TEXT, expires_at TEXT, revoked INTEGER DEFAULT 0,
            uses INTEGER DEFAULT 0, last_used_at TEXT, last_ip TEXT DEFAULT '')""", ()),
        (f"""CREATE TABLE IF NOT EXISTS devices (
            id {pk}, key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL, ip TEXT DEFAULT '', first_seen TEXT, last_seen TEXT,
            UNIQUE (key_id, device_id))""", ()),
        (f"""CREATE TABLE IF NOT EXISTS logs (
            id {pk}, ts TEXT, action TEXT, detail TEXT DEFAULT '', ip TEXT DEFAULT '')""", ()),
        ("CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (ts)", ()),
    ])


_ready = False


def ensure_db():
    global _ready
    if not _ready:
        init_db()
        _ready = True


try:
    ensure_db()
except Exception as exc:  # retried on first request
    print("DB init failed, will retry:", exc, file=sys.stderr)


def log(action, detail=""):
    try:
        run("INSERT INTO logs (ts, action, detail, ip) VALUES (?,?,?,?)",
            (iso(now()), action, str(detail)[:300], client_ip()), fetch="none")
        if random.random() < 0.02:
            prune_logs()
    except Exception as exc:
        print("log failed:", exc, file=sys.stderr)


def prune_logs(keep=3000):
    row = run("SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?", (keep,), fetch="one")
    if row:
        run("DELETE FROM logs WHERE id <= ?", (row["id"],), fetch="none")


# --------------------------------------------------------------------------- helpers
def client_ip():
    return (request.remote_addr or "")[:64]


_hits = {}


def limited(bucket, limit, window):
    t = time.time()
    arr = [x for x in _hits.get(bucket, []) if t - x < window]
    if len(arr) >= limit:
        _hits[bucket] = arr
        return True
    arr.append(t)
    _hits[bucket] = arr
    if len(_hits) > 5000:
        for k in list(_hits)[:2500]:
            _hits.pop(k, None)
    return False


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def admin_api(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("auth"):
            return jsonify(ok=False, error="unauthorized"), 401
        if request.method != "GET":
            sent = request.headers.get("X-CSRF", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")):
                return jsonify(ok=False, error="csrf"), 403
        return fn(*a, **kw)
    return wrapper


@app.before_request
def _db_guard():
    if request.endpoint not in ("static", None):
        try:
            ensure_db()
        except Exception as exc:
            return jsonify(ok=False, error="database_unavailable", detail=str(exc)[:120]), 503


@app.after_request
def _headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.path in ("/connect", "/api/verify"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    if request.path.startswith(("/api/admin", "/panel", "/login")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def detect_host():
    e = os.environ
    table = [
        ("RENDER", "Render", lambda: {"service": e.get("RENDER_SERVICE_NAME"), "external_url": e.get("RENDER_EXTERNAL_URL"),
                                      "instance": e.get("RENDER_INSTANCE_ID")}),
        ("RAILWAY_ENVIRONMENT", "Railway", lambda: {"service": e.get("RAILWAY_SERVICE_NAME"), "external_url": e.get("RAILWAY_PUBLIC_DOMAIN")}),
        ("DYNO", "Heroku", lambda: {"service": e.get("HEROKU_APP_NAME"), "instance": e.get("DYNO")}),
        ("FLY_APP_NAME", "Fly.io", lambda: {"service": e.get("FLY_APP_NAME"), "region": e.get("FLY_REGION")}),
        ("KOYEB_APP_NAME", "Koyeb", lambda: {"service": e.get("KOYEB_APP_NAME")}),
        ("VERCEL", "Vercel", lambda: {"service": e.get("VERCEL_URL")}),
    ]
    for var, name, extra in table:
        if e.get(var):
            info = {k: v for k, v in extra().items() if v}
            return {"name": name, **info}
    return {"name": "Local machine"}


def base_url():
    return request.url_root.rstrip("/")


# --------------------------------------------------------------------------- key model
ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def make_key(prefix):
    parts = ["".join(secrets.choice(ALPHA) for _ in range(4)) for _ in range(4)]
    return "-".join([prefix] + parts)


def key_state(row):
    if row["revoked"]:
        return "revoked"
    if row["expires_at"] and row["expires_at"] <= iso(now()):
        return "expired"
    return "active"


def key_out(row, dev_count=0):
    exp = row["expires_at"]
    days_left = None
    if exp:
        days_left = max(0, (datetime.fromisoformat(exp) - now()).days)
    return {
        "id": row["id"], "key": row["key"], "label": row["label"] or "", "plan": row["plan"] or "standard",
        "status": key_state(row), "max_devices": row["max_devices"], "devices": dev_count,
        "created_at": z(row["created_at"]), "expires_at": z(exp), "days_left": days_left,
        "lifetime": exp is None, "uses": row["uses"], "last_used_at": z(row["last_used_at"]),
        "last_ip": row["last_ip"] or "",
    }


def clean_int(v, default, lo, hi):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def clean_text(v, n):
    return "".join(ch for ch in str(v or "") if ch.isprintable()).strip()[:n]


# --------------------------------------------------------------------------- pages
@app.route("/")
def home():
    return redirect(url_for("panel" if session.get("auth") else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("panel"))
    error = None
    if request.method == "POST":
        if limited("login:" + client_ip(), 6, 300):
            error = "Too many attempts. Wait a few minutes and try again."
        elif not hmac.compare_digest(request.form.get("csrf", ""), csrf_token()):
            error = "This page expired. Reload it and try again."
        else:
            u = request.form.get("username", "").strip().upper().encode()
            p = request.form.get("password", "").encode()
            ok_u = hmac.compare_digest(u, ADMIN_USER.upper().encode())
            ok_p = hmac.compare_digest(p, ADMIN_PASS.encode())
            if ok_u and ok_p:
                session.clear()
                session.permanent = True
                session["auth"] = True
                csrf_token()
                log("login", "admin signed in")
                return redirect(url_for("panel"))
            log("login_fail", "bad credentials")
            error = "Wrong username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(ok=True)


@app.route("/panel")
def panel():
    if not session.get("auth"):
        return redirect(url_for("login"))
    return render_template("panel.html")


@app.route("/health")
def health():
    try:
        run("SELECT 1 AS x", fetch="one")
        return jsonify(ok=True, db="postgres" if PG else "sqlite")
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)[:120]), 503


# --------------------------------------------------------------------------- public connect API
@app.route("/connect", methods=["GET", "POST", "OPTIONS"])
@app.route("/api/verify", methods=["POST", "OPTIONS"])
def connect():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "GET":
        return jsonify(ok=True, service="MAFIA Control", online=True, connect_url=base_url() + "/connect",
                       method="POST", body={"key": "string", "device_id": "string"},
                       server_time=z(iso(now())))

    if limited("verify:" + client_ip(), 60, 60):
        return jsonify(ok=False, error="rate_limited", message="Too many requests."), 429

    data = request.get_json(silent=True) or request.form or {}
    key = clean_text(data.get("key"), 64).upper()
    device = clean_text(data.get("device_id") or data.get("hwid"), 128)
    if not key or not device:
        return jsonify(ok=False, error="bad_request", message="key and device_id are required."), 400

    row = run("SELECT * FROM keys WHERE key = ?", (key,), fetch="one")
    if not row:
        log("verify_fail", f"unknown key {key[:24]}")
        return jsonify(ok=False, error="invalid_key", message="This key does not exist."), 404
    st = key_state(row)
    if st != "active":
        log("verify_fail", f"{key} {st}")
        return jsonify(ok=False, error=st, message=f"This key is {st}."), 403

    stamp = iso(now())
    dev = run("SELECT id FROM devices WHERE key_id = ? AND device_id = ?", (row["id"], device), fetch="one")
    if dev:
        run("UPDATE devices SET last_seen = ?, ip = ? WHERE id = ?", (stamp, client_ip(), dev["id"]), fetch="none")
    else:
        count = run("SELECT COUNT(*) AS n FROM devices WHERE key_id = ?", (row["id"],), fetch="one")["n"]
        if count >= row["max_devices"]:
            log("verify_fail", f"{key} device limit")
            return jsonify(ok=False, error="device_limit",
                           message="This key is already used on the maximum number of devices."), 403
        try:
            run("INSERT INTO devices (key_id, device_id, ip, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (row["id"], device, client_ip(), stamp, stamp), fetch="none")
        except Exception:
            pass  # simultaneous first request from same device
    run("UPDATE keys SET uses = uses + 1, last_used_at = ?, last_ip = ? WHERE id = ?",
        (stamp, client_ip(), row["id"]), fetch="none")
    log("verify_ok", key)
    out = key_out(row)
    return jsonify(ok=True, status="active", key=row["key"], plan=out["plan"], label=out["label"],
                   lifetime=out["lifetime"], expires_at=out["expires_at"], days_left=out["days_left"],
                   server_time=z(stamp))


# --------------------------------------------------------------------------- admin API
@app.route("/api/admin/overview")
@admin_api
def api_overview():
    stamp = iso(now())
    c = run("""SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END),0) AS revoked,
                      COALESCE(SUM(CASE WHEN revoked = 0 AND expires_at IS NOT NULL AND expires_at <= ? THEN 1 ELSE 0 END),0) AS expired
               FROM keys""", (stamp,), fetch="one")
    total, revoked, expired = int(c["total"]), int(c["revoked"]), int(c["expired"])
    devices = run("SELECT COUNT(*) AS n FROM devices", fetch="one")["n"]
    since = iso(now() - timedelta(days=6)).split("T")[0] + "T00:00:00"
    rows = run("SELECT ts, action FROM logs WHERE action IN ('verify_ok','verify_fail') AND ts >= ?", (since,))
    series = {}
    for i in range(7):
        d = (now() - timedelta(days=6 - i)).date().isoformat()
        series[d] = {"day": d, "ok": 0, "fail": 0}
    for r in rows:
        d = r["ts"][:10]
        if d in series:
            series[d]["ok" if r["action"] == "verify_ok" else "fail"] += 1
    today = now().date().isoformat()
    return jsonify(ok=True,
                   stats={"total": total, "active": total - revoked - expired, "revoked": revoked,
                          "expired": expired, "devices": devices,
                          "checks_today": series[today]["ok"] + series[today]["fail"]},
                   series=list(series.values()),
                   connect_url=base_url() + "/connect", host=detect_host(),
                   system={"database": "PostgreSQL" if PG else "SQLite (local file)",
                           "python": platform.python_version(),
                           "uptime_seconds": int(time.time() - STARTED), "server_time": z(stamp)})


@app.route("/api/admin/keys", methods=["GET"])
@admin_api
def api_keys():
    q = clean_text(request.args.get("q"), 60).lower()
    status = request.args.get("status", "all")
    stamp = iso(now())
    where, args = [], []
    if q:
        where.append("(LOWER(k.key) LIKE ? OR LOWER(k.label) LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if status == "revoked":
        where.append("k.revoked = 1")
    elif status == "expired":
        where.append("k.revoked = 0 AND k.expires_at IS NOT NULL AND k.expires_at <= ?")
        args.append(stamp)
    elif status == "active":
        where.append("k.revoked = 0 AND (k.expires_at IS NULL OR k.expires_at > ?)")
        args.append(stamp)
    sql = ("SELECT k.*, (SELECT COUNT(*) FROM devices d WHERE d.key_id = k.id) AS dev_count FROM keys k"
           + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY k.id DESC LIMIT 500")
    rows = run(sql, tuple(args))
    return jsonify(ok=True, keys=[key_out(r, r["dev_count"]) for r in rows])


@app.route("/api/admin/keys", methods=["POST"])
@admin_api
def api_create():
    d = request.get_json(silent=True) or {}
    count = clean_int(d.get("count"), 1, 1, 200)
    days = clean_int(d.get("days"), 30, 0, 36500)
    max_dev = clean_int(d.get("max_devices"), 1, 1, 1000)
    plan = clean_text(d.get("plan"), 32) or "standard"
    label = clean_text(d.get("label"), 120)
    prefix = "".join(ch for ch in str(d.get("prefix") or "MAFIA").upper() if ch.isalnum())[:8] or "MAFIA"
    created = now()
    expires = iso(created + timedelta(days=days)) if days > 0 else None
    made = []
    for _ in range(count):
        for _try in range(8):
            k = make_key(prefix)
            try:
                run("INSERT INTO keys (key, label, plan, max_devices, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                    (k, label, plan, max_dev, iso(created), expires), fetch="none")
                made.append(k)
                break
            except Exception:
                continue
    log("keys_created", f"{len(made)} x {plan}, {'lifetime' if days == 0 else str(days) + ' days'}")
    return jsonify(ok=True, keys=made)


def _load(key_id):
    return run("SELECT * FROM keys WHERE id = ?", (key_id,), fetch="one")


@app.route("/api/admin/keys/<int:key_id>", methods=["GET"])
@admin_api
def api_key_detail(key_id):
    row = _load(key_id)
    if not row:
        return jsonify(ok=False, error="not_found"), 404
    devs = run("SELECT id, device_id, ip, first_seen, last_seen FROM devices WHERE key_id = ? ORDER BY id", (key_id,))
    for dv in devs:
        dv["first_seen"], dv["last_seen"] = z(dv["first_seen"]), z(dv["last_seen"])
    return jsonify(ok=True, key=key_out(row, len(devs)), devices=devs)


@app.route("/api/admin/keys/<int:key_id>", methods=["PATCH"])
@admin_api
def api_key_update(key_id):
    row = _load(key_id)
    if not row:
        return jsonify(ok=False, error="not_found"), 404
    d = request.get_json(silent=True) or {}
    sets, args = [], []
    if "label" in d:
        sets.append("label = ?"); args.append(clean_text(d["label"], 120))
    if "plan" in d:
        sets.append("plan = ?"); args.append(clean_text(d["plan"], 32) or "standard")
    if "max_devices" in d:
        sets.append("max_devices = ?"); args.append(clean_int(d["max_devices"], row["max_devices"], 1, 1000))
    if d.get("lifetime"):
        sets.append("expires_at = NULL")
    elif d.get("add_days") not in (None, "", 0, "0"):
        add = clean_int(d["add_days"], 0, -36500, 36500)
        base = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else now()
        if row["expires_at"] and base < now():
            base = now()
        sets.append("expires_at = ?"); args.append(iso(base + timedelta(days=add)))
    if "revoked" in d:
        sets.append("revoked = ?"); args.append(1 if d["revoked"] else 0)
    if sets:
        run(f"UPDATE keys SET {', '.join(sets)} WHERE id = ?", tuple(args + [key_id]), fetch="none")
        log("key_updated", f"{row['key']}: {', '.join(s.split(' ')[0] for s in sets)}")
    return jsonify(ok=True)


@app.route("/api/admin/keys/<int:key_id>/reset-devices", methods=["POST"])
@admin_api
def api_reset_devices(key_id):
    row = _load(key_id)
    if not row:
        return jsonify(ok=False, error="not_found"), 404
    n = run("DELETE FROM devices WHERE key_id = ?", (key_id,), fetch="none")
    log("devices_reset", f"{row['key']} ({n})")
    return jsonify(ok=True, removed=n)


@app.route("/api/admin/devices/<int:dev_id>", methods=["DELETE"])
@admin_api
def api_remove_device(dev_id):
    run("DELETE FROM devices WHERE id = ?", (dev_id,), fetch="none")
    log("device_removed", dev_id)
    return jsonify(ok=True)


@app.route("/api/admin/keys/<int:key_id>", methods=["DELETE"])
@admin_api
def api_key_delete(key_id):
    row = _load(key_id)
    if not row:
        return jsonify(ok=False, error="not_found"), 404
    run_many([("DELETE FROM devices WHERE key_id = ?", (key_id,)), ("DELETE FROM keys WHERE id = ?", (key_id,))])
    log("key_deleted", row["key"])
    return jsonify(ok=True)


@app.route("/api/admin/logs")
@admin_api
def api_logs():
    kind = request.args.get("kind", "all")
    sql = "SELECT ts, action, detail, ip FROM logs"
    args = ()
    if kind == "verify":
        sql += " WHERE action IN ('verify_ok','verify_fail')"
    elif kind == "admin":
        sql += " WHERE action NOT IN ('verify_ok','verify_fail')"
    rows = run(sql + " ORDER BY id DESC LIMIT 200", args)
    for r in rows:
        r["ts"] = z(r["ts"])
    return jsonify(ok=True, logs=rows)


@app.route("/api/admin/export.csv")
@admin_api
def api_export():
    rows = run("SELECT * FROM keys ORDER BY id")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["key", "label", "plan", "status", "max_devices", "created_at", "expires_at", "uses", "last_used_at"])
    for r in rows:
        w.writerow([r["key"], r["label"], r["plan"], key_state(r), r["max_devices"], z(r["created_at"]),
                    z(r["expires_at"]) or "lifetime", r["uses"], z(r["last_used_at"]) or ""])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=mafia-keys.csv"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
