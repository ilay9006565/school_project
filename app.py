from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import os
import bcrypt
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
DATABASE_URL = os.environ.get("DATABASE_URL")
ONLINE_TIMEOUT = 5  # minutes

class DBWrapper:
    def __init__(self, conn):
        self.conn = conn
    def execute(self, query, params=None):
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(query, params)
        return cur

@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield DBWrapper(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'host',
                created_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS client_ips (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                ip        TEXT NOT NULL,
                logged_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS online_sessions (
                user_id     INTEGER PRIMARY KEY,
                username    TEXT NOT NULL,
                role        TEXT NOT NULL,
                ip          TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        # Tracks active control pairings: one controller → one host
        conn.execute("""
            CREATE TABLE IF NOT EXISTS control_sessions (
                host_user_id        INTEGER PRIMARY KEY,
                controller_user_id  INTEGER NOT NULL,
                controller_username TEXT NOT NULL,
                established_at      TEXT NOT NULL,
                FOREIGN KEY(host_user_id)       REFERENCES users(id),
                FOREIGN KEY(controller_user_id) REFERENCES users(id)
            )
        """)
        # Pending requests: controller → host (waiting for host to accept/decline)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS control_requests (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                host_user_id        INTEGER NOT NULL,
                controller_user_id  INTEGER NOT NULL,
                controller_username TEXT NOT NULL,
                requested_at        TEXT NOT NULL,
                UNIQUE(host_user_id, controller_user_id)
            )
        """)

def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def get_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr



def mark_online(user_id, username, role, ip):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("""
            INSERT INTO online_sessions (user_id, username, role, ip, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                ip=excluded.ip, last_seen=excluded.last_seen, role=excluded.role
        """, (user_id, username, role, ip, now))

def mark_offline(user_id):
    with get_db() as conn:
        conn.execute("DELETE FROM online_sessions WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM control_sessions  WHERE host_user_id=? OR controller_user_id=?",
                     (user_id, user_id))
        conn.execute("DELETE FROM control_requests  WHERE host_user_id=? OR controller_user_id=?",
                     (user_id, user_id))

def get_online_users():
    cutoff = (datetime.now() - timedelta(minutes=ONLINE_TIMEOUT)).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("DELETE FROM online_sessions WHERE last_seen < ?", (cutoff,))
        rows = conn.execute("""
            SELECT o.user_id, o.username, o.role, o.ip, o.last_seen,
                   cs.controller_username AS controlled_by
            FROM   online_sessions o
            LEFT JOIN control_sessions cs ON cs.host_user_id = o.user_id
            ORDER BY o.role DESC, o.last_seen DESC
        """).fetchall()
    return rows


def get_my_control_state(user_id, role):
    """Return relevant control info for the current user."""
    with get_db() as conn:
        if role == "controller":
            cs = conn.execute(
                "SELECT host_user_id FROM control_sessions WHERE controller_user_id=?",
                (user_id,)
            ).fetchone()
            controlling = cs["host_user_id"] if cs else None

            pending = conn.execute("""
                SELECT cr.host_user_id, o.username AS host_username
                FROM   control_requests cr
                JOIN   online_sessions  o ON o.user_id = cr.host_user_id
                WHERE  cr.controller_user_id = ?
            """, (user_id,)).fetchall()
            return {"controlling": controlling, "pending_sent": [dict(r) for r in pending]}

        else:  # host
            cs = conn.execute(
                "SELECT controller_username FROM control_sessions WHERE host_user_id=?",
                (user_id,)
            ).fetchone()
            controlled_by = cs["controller_username"] if cs else None

            incoming = conn.execute("""
                SELECT cr.id, cr.controller_user_id, cr.controller_username
                FROM   control_requests cr
                WHERE  cr.host_user_id = ?
            """, (user_id,)).fetchall()
            return {"controlled_by": controlled_by, "pending_requests": [dict(r) for r in incoming]}


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        role     = request.form.get("role", "host")
        if role not in ("host", "controller"):
            role = "host"
        if not username or not password:
            flash("All fields are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        else:
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password, role, created_at) VALUES (?,?,?,?)",
                        (username, hash_pw(password), role, datetime.now().isoformat())
                    )
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already taken.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()
        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            ip = get_ip()
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO client_ips (user_id, ip, logged_at) VALUES (?,?,?)",
                    (user["id"], ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
            mark_online(user["id"], user["username"], user["role"], ip)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    mark_online(session["user_id"], session["username"], session["role"], get_ip())
    online_users  = get_online_users()
    control_state = get_my_control_state(session["user_id"], session["role"])
    with get_db() as conn:
        ips = conn.execute(
            "SELECT ip, logged_at FROM client_ips WHERE user_id=? ORDER BY logged_at DESC",
            (session["user_id"],)
        ).fetchall()
    return render_template("dashboard.html",
                           username=session["username"],
                           role=session["role"],
                           ips=ips,
                           online_users=online_users,
                           control_state=control_state,
                           online_timeout=ONLINE_TIMEOUT)

# ── Heartbeat (every 30 s) ──

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    if "user_id" not in session:
        return jsonify({"status": "offline"}), 401
    mark_online(session["user_id"], session["username"], session["role"], get_ip())
    online = []
    for r in get_online_users():
        online.append({
            "user_id":      r["user_id"],
            "username":     r["username"],
            "role":         r["role"],
            "ip":           r["ip"],
            "controlled_by": r["controlled_by"]
        })
    control_state = get_my_control_state(session["user_id"], session["role"])
    return jsonify({"status": "ok", "online": online, "control_state": control_state})

# ── Control request: controller → host ──

@app.route("/control/request/<int:host_id>", methods=["POST"])
def control_request(host_id):
    if "user_id" not in session or session["role"] != "controller":
        return jsonify({"error": "forbidden"}), 403

    with get_db() as conn:
        # Check host is online
        host = conn.execute(
            "SELECT username FROM online_sessions WHERE user_id=? AND role='host'", (host_id,)
        ).fetchone()
        if not host:
            return jsonify({"error": "Host not found or offline"}), 404

        # Check host not already controlled
        occupied = conn.execute(
            "SELECT controller_username FROM control_sessions WHERE host_user_id=?", (host_id,)
        ).fetchone()
        if occupied:
            return jsonify({"error": "occupied", "by": occupied["controller_username"]}), 409

        # Insert pending request
        try:
            conn.execute("""
                INSERT INTO control_requests (host_user_id, controller_user_id, controller_username, requested_at)
                VALUES (?,?,?,?)
            """, (host_id, session["user_id"], session["username"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except sqlite3.IntegrityError:
            return jsonify({"error": "Request already pending"}), 409

    return jsonify({"status": "requested", "host": host["username"]})

# ── Host accepts or declines ──

@app.route("/control/respond/<int:req_id>/<action>", methods=["POST"])
def control_respond(req_id, action):
    if "user_id" not in session or session["role"] != "host":
        return jsonify({"error": "forbidden"}), 403
    if action not in ("accept", "decline"):
        return jsonify({"error": "invalid action"}), 400

    with get_db() as conn:
        req = conn.execute(
            "SELECT * FROM control_requests WHERE id=? AND host_user_id=?",
            (req_id, session["user_id"])
        ).fetchone()
        if not req:
            return jsonify({"error": "Request not found"}), 404

        conn.execute("DELETE FROM control_requests WHERE id=?", (req_id,))

        if action == "accept":
            # Remove any previous control session for this host
            conn.execute("DELETE FROM control_sessions WHERE host_user_id=?", (session["user_id"],))
            conn.execute("""
                INSERT INTO control_sessions (host_user_id, controller_user_id, controller_username, established_at)
                VALUES (?,?,?,?)
            """, (session["user_id"], req["controller_user_id"],
                  req["controller_username"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            # Fetch IPs so the Python scripts know who to connect to
            host_ip = conn.execute(
                "SELECT ip FROM online_sessions WHERE user_id=?", (session["user_id"],)
            ).fetchone()
            ctrl_ip = conn.execute(
                "SELECT ip FROM online_sessions WHERE user_id=?", (req["controller_user_id"],)
            ).fetchone()

            return jsonify({
                "status": "accepted",
                "host_ip": host_ip["ip"] if host_ip else None,
                "controller_ip": ctrl_ip["ip"] if ctrl_ip else None,
                "controller_username": req["controller_username"]
            })

    return jsonify({"status": "declined"})

# ── Release control ──

@app.route("/control/release", methods=["POST"])
def control_release():
    if "user_id" not in session:
        return jsonify({"error": "forbidden"}), 403
    uid  = session["user_id"]
    role = session["role"]
    with get_db() as conn:
        if role == "host":
            conn.execute("DELETE FROM control_sessions WHERE host_user_id=?", (uid,))
        else:
            conn.execute("DELETE FROM control_sessions WHERE controller_user_id=?", (uid,))
    return jsonify({"status": "released"})

# mainHost / mainController call this to get connection info once paired

@app.route("/api/connection_info", methods=["GET"])
def connection_info():
    """
    Python scripts (mainHost / mainController) poll this with ?username=X&role=Y
    Returns pairing info once a control session is established.
    """
    username = request.args.get("username", "")
    role     = request.args.get("role", "")
    with get_db() as conn:
        user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            return jsonify({"paired": False, "error": "unknown user"}), 404

        uid = user["id"]
        if role == "host":
            cs = conn.execute("""
                SELECT cs.controller_username, o.ip AS controller_ip
                FROM   control_sessions cs
                JOIN   online_sessions  o ON o.user_id = cs.controller_user_id
                WHERE  cs.host_user_id = ?
            """, (uid,)).fetchone()
            if cs:
                return jsonify({"paired": True, "connect_to": cs["controller_ip"],
                                "peer_username": cs["controller_username"]})
        else:  # controller
            cs = conn.execute("""
                SELECT o.ip AS host_ip, o.username AS host_username
                FROM   control_sessions cs
                JOIN   online_sessions  o ON o.user_id = cs.host_user_id
                WHERE  cs.controller_user_id = ?
            """, (uid,)).fetchone()
            if cs:
                return jsonify({"paired": True, "connect_to": cs["host_ip"],
                                "peer_username": cs["host_username"]})

    return jsonify({"paired": False})

@app.route("/logout")
def logout():
    if "user_id" in session:
        mark_offline(session["user_id"])
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
