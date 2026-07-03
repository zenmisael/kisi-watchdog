import eventlet
eventlet.monkey_patch()

import asyncio, threading, hashlib, os, secrets, sqlite3, requests, socket, random, time, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash

# Load a local .env (if present) so `python borg.py` picks up secrets the same
# way docker-compose's env_file does. Real env vars take precedence over .env.
def _load_dotenv(path=".env"):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass

_load_dotenv()

DB = "data/monitor.db"
FAIL_THRESHOLD = 3
MIN_OUTAGE_DURATION = 7
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Zabbix Credentials (configured via environment)
ZABBIX_URL = os.getenv("ZABBIX_URL", "https://zabbix.kisi.co.id/api_jsonrpc.php")
ZABBIX_USER = os.getenv("ZABBIX_USER", "admin")
ZABBIX_PASS = os.getenv("ZABBIX_PASS")

# MARK — Zabbix "all offline" gotcha: without ZABBIX_PASS there is no auth
# token, so Zabbix checks return "unknown" and targets can never come online.
# (Zabbix 5.0 login uses the "user" param, already sent below.)
if not ZABBIX_PASS:
    print("WARNING: ZABBIX_PASS is not set — Zabbix targets cannot be checked. Set it in .env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=1 when served over HTTPS (recommended in prod).
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# --- AUTH HELPERS ---
def require_login(f):
    @wraps(f)
    def wrapper(*a, **k):
        if "user" not in session:
            return jsonify({"error": "authentication required"}), 401
        return f(*a, **k)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*a, **k):
        if "user" not in session:
            return jsonify({"error": "authentication required"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "admin privileges required"}), 403
        return f(*a, **k)
    return wrapper

# --- PASSWORD HASHING (werkzeug, with legacy sha256 fallback) ---
def hash_password(p):
    return generate_password_hash(p)

def _is_legacy_sha256(stored):
    return len(stored) == 64 and all(ch in "0123456789abcdef" for ch in stored.lower())

def verify_password(stored, provided):
    if _is_legacy_sha256(stored):
        return hashlib.sha256(provided.encode()).hexdigest() == stored
    try:
        return check_password_hash(stored, provided)
    except Exception:
        return False

# --- CSRF PROTECTION ---
# The dashboard changes state via same-origin fetch() POSTs that carry no CSRF
# token in the page. Rather than alter the frontend, we rely on the
# SESSION_COOKIE_SAMESITE="Lax" cookie set above: browsers will not attach the
# session cookie to cross-site POST requests, so a forged request arrives
# without a valid session and is rejected by @require_login / @require_admin.
# (For stricter defense later, add an X-CSRFToken header to the fetch calls.)

loop = asyncio.new_event_loop()
tasks = {}
task_owners = {}
active_monitors = set()

# --- BORG GOLDEN RULE: SINGLETON PROTECTION ---
MONITOR_STARTED = False

def get_db():
    os.makedirs("data", exist_ok=True)
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    return c

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, target TEXT, monitor_detail TEXT, down_time TEXT, up_time TEXT, duration TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password TEXT, role TEXT)")
    
    c.execute("PRAGMA table_info(targets)")
    columns = [col[1] for col in c.fetchall()]
    
    if not columns:
        c.execute("""CREATE TABLE targets(
            id INTEGER PRIMARY KEY, name TEXT, description TEXT,
            monitor_type TEXT, monitor_port TEXT, status TEXT DEFAULT 'Online',
            last_down TEXT, last_check TEXT, fail_count INTEGER DEFAULT 0,
            maintenance INTEGER DEFAULT 0, check_interval INTEGER DEFAULT 10, timeout INTEGER DEFAULT 2,
            zabbix_item_key TEXT, zabbix_host_id TEXT,
            UNIQUE(name, monitor_type, monitor_port, zabbix_item_key)
        )""")
    else:
        if "zabbix_host_id" not in columns:
            c.execute("ALTER TABLE targets ADD COLUMN zabbix_host_id TEXT")

    def ensure(u, p, r):
        if not c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            c.execute("INSERT INTO users VALUES(?,?,?)", (u, hash_password(p), r))
    ensure("admin", os.getenv("ADMIN_PASSWORD", "admin123"), "admin")
    ensure("viewer", os.getenv("VIEWER_PASSWORD", "viewer123"), "viewer")
    conn.commit(); conn.close()

init_db()

# --- ZABBIX HELPERS ---
# Cache the auth token instead of logging in on every check (which otherwise
# opens a new Zabbix session every poll cycle).
_zbx_cache = {"token": None, "ts": 0.0}
ZBX_TOKEN_TTL = 300  # seconds; re-login after this

def get_zabbix_token(force=False):
    now = time.time()
    if not force and _zbx_cache["token"] and (now - _zbx_cache["ts"]) < ZBX_TOKEN_TTL:
        return _zbx_cache["token"]
    try:
        auth_p = {"jsonrpc": "2.0", "method": "user.login", "params": {"user": ZABBIX_USER, "password": ZABBIX_PASS}, "id": 1}
        r = requests.post(ZABBIX_URL, json=auth_p, timeout=5, verify=False).json()
        tok = r.get('result')
        if tok:
            _zbx_cache["token"] = tok
            _zbx_cache["ts"] = now
        return tok
    except: return None

@app.route("/zabbix_hosts")
@require_login
def list_zabbix_hosts():
    if session.get("role") != "admin": return jsonify([])
    token = get_zabbix_token()
    if not token: return jsonify([])
    try:
        payload = {"jsonrpc": "2.0", "method": "host.get", "params": {"output": ["hostid", "name"], "filter": {"status": 0}, "sortfield": "name"}, "auth": token, "id": 1}
        resp = requests.post(ZABBIX_URL, json=payload, timeout=5, verify=False).json()
        return jsonify(resp.get('result', []))
    except: return jsonify([])

@app.route("/zabbix_items/<hostid>")
@require_login
def list_zabbix_items(hostid):
    if session.get("role") != "admin": return jsonify([])
    token = get_zabbix_token()
    if not token: return jsonify([])
    try:
        payload = {"jsonrpc": "2.0", "method": "item.get", "params": {"hostids": hostid, "output": ["name", "key_"], "filter": {"status": 0}, "sortfield": "name"}, "auth": token, "id": 1}
        resp = requests.post(ZABBIX_URL, json=payload, timeout=5, verify=False).json()
        return jsonify(resp.get('result', []))
    except: return jsonify([])

# --- MONITORING LOGIC ---
async def check_zabbix_status(hostid, item_key):

    def _fetch():

        token = get_zabbix_token()

        # No token = can't reach/authenticate Zabbix. Return None ("unknown")
        # so monitor_target keeps the last status instead of flipping every
        # Zabbix target to Offline (and spamming incidents/Telegram).
        if not token:
            return None
        if not hostid:
            return False

        try:

            item_p = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "hostids": hostid,
                    "search": {
                        "key_": item_key
                    },
                    "output": ["lastvalue"]
                },
                "auth": token,
                "id": 1
            }

            res = requests.post(
                ZABBIX_URL,
                json=item_p,
                timeout=5,
                verify=False
            ).json()

            items = res.get("result", [])

            if not items:
                return False

            val_raw = str(
                items[0].get("lastvalue", "")
            ).strip().lower()

            # ZABBIX RESOURCE MONITORING VIA TRIGGER STATE
            resource_keys = [
                "utilization",
                "usage",
                "pused",
                "util",
                "load",
                "memory",
                "mem",
                "ram",
                "disk",
                "storage",
                "cpu"
            ]

            if any(
                k in item_key.lower()
                for k in resource_keys
            ):

                trigger_p = {
                    "jsonrpc": "2.0",
                    "method": "trigger.get",
                    "params": {
                        "hostids": hostid,
                        "output": [
                            "description",
                            "value"
                        ]
                    },
                    "auth": token,
                    "id": 2
                }

                trig_res = requests.post(
                    ZABBIX_URL,
                    json=trigger_p,
                    timeout=5,
                    verify=False
                ).json()

                triggers = trig_res.get(
                    "result",
                    []
                )

                trigger_keywords = []

                ik = item_key.lower()

                if "cpu" in ik or "load" in ik:

                    trigger_keywords = [
                        "cpu",
                        "load"
                    ]

                elif (
                    "memory" in ik or
                    "mem" in ik or
                    "ram" in ik
                ):

                    trigger_keywords = [
                        "memory",
                        "ram"
                    ]

                elif (
                    "disk" in ik or
                    "storage" in ik or
                    "space" in ik or
                    "pused" in ik
                ):

                    trigger_keywords = [
                        "disk",
                        "storage",
                        "space"
                    ]

                else:

                    trigger_keywords = [
                        item_key.lower()
                    ]

                for trig in triggers:

                    desc = str(
                        trig.get(
                            "description",
                            ""
                        )
                    ).lower()

                    active = (
                        str(
                            trig.get("value")
                        ) == "1"
                    )

                    if not active:
                        continue

                    if any(
                        k in desc
                        for k in trigger_keywords
                    ):

                        return False

                return True

            return val_raw in [
                "1",
                "connected",
                "up",
                "running",
                "online",
                "ok"
            ]

        except Exception as e:

            print(
                "ZABBIX CHECK ERROR:",
                e
            )

            # Network/API error — treat as "unknown", not a real outage.
            return None

    return await loop.run_in_executor(
        None,
        _fetch
    )

async def check_icmp(host, timeout):
    try:
        p = await asyncio.create_subprocess_exec("ping", "-c", "3", "-i", "0.2", "-W", str(timeout), host, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await p.wait(); return p.returncode == 0
    except: return False

async def check_tcp(host, port, timeout):
    try:
        def _connect():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(float(timeout))
            res = s.connect_ex((host, int(port))); s.close(); return res == 0
        return await loop.run_in_executor(None, _connect)
    except: return False


async def check_http_json(url, timeout):

    try:

        def _fetch():

            r = requests.get(
                url,
                timeout=float(timeout),
                verify=False
            )

            if r.status_code != 200:
                return False

            data = r.json()

            status = str(
                data.get("status", "")
            ).lower()

            return status == "ok"

        return await loop.run_in_executor(
            None,
            _fetch
        )

    except Exception as e:

        print(
            "HTTP JSON ERROR:",
            e
        )

        return False


async def monitor_target(tid):

    my_owner = task_owners.get(tid)

    # HARD SINGLETON LOCK
    if tid in active_monitors:
        return

    active_monitors.add(tid)

    await asyncio.sleep(random.uniform(0.5, 1.5))

    try:

        while True:

            # KILL DUPLICATE/ZOMBIE TASKS
            if task_owners.get(tid) != my_owner:
                active_monitors.discard(tid)
                return

            try:

                conn = get_db()
                c = conn.cursor()

                t = c.execute(
                    "SELECT * FROM targets WHERE id=?",
                    (tid,)
                ).fetchone()

                if not t:
                    conn.close()
                    active_monitors.discard(tid)
                    return

                if t["maintenance"]:
                    conn.close()
                    await asyncio.sleep(
                        t["check_interval"]
                    )
                    continue

                m_type = t['monitor_type'].upper()

                if m_type == "ZABBIX":

                    ok = await check_zabbix_status(
                        t["zabbix_host_id"],
                        t["zabbix_item_key"]
                    )

                    m_info = (
                        f"ZBX:{t['zabbix_item_key']}"
                    )

                elif m_type == "HTTP_JSON":

                    ok = await check_http_json(
                        t["name"],
                        t["timeout"]
                    )
                    
                    m_info = "HTTP_JSON"

                elif m_type == "TCP":

                    ok = await check_tcp(
                        t["name"],
                        t["monitor_port"],
                        t["timeout"]
                    )

                    m_info = (
                        f"TCP:{t['monitor_port']}"
                    )

                else:

                    ok = await check_icmp(
                        t["name"],
                        t["timeout"]
                    )

                    m_info = "ICMP"

                now = datetime.now()

                ts = now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                if ok is None:

                    # "Unknown" (e.g. Zabbix unreachable/unauthenticated):
                    # record the check time but keep the last status. Do NOT
                    # count a failure, flip to Offline, or fire an alert.
                    c.execute(
                        "UPDATE targets SET last_check=? WHERE id=?",
                        (ts, tid)
                    )

                elif ok:

                    if t["status"] == "Offline":

                        down_dt = datetime.strptime(
                            t["last_down"],
                            "%Y-%m-%d %H:%M:%S"
                        )

                        dur_str = str(
                            now - down_dt
                        ).split(".")[0]

                        c.execute("""
                        UPDATE targets
                        SET status='Online',
                            fail_count=0,
                            last_down=NULL,
                            last_check=?
                        WHERE id=?
                        """, (
                            ts,
                            tid
                        ))

                        if c.rowcount > 0:

                            conn.commit()

                            if (
                                now - down_dt
                            ).total_seconds() >= MIN_OUTAGE_DURATION:

                                c.execute("""
                                UPDATE incidents
                                SET up_time=?,
                                    duration=?
                                WHERE target=?
                                AND up_time IS NULL
                                """, (
                                    ts,
                                    dur_str,
                                    t["name"]
                                ))

                                conn.commit()

                            send_telegram(
                                t['name'],
                                t['description'],
                                m_info,
                                ts,
                                dur_str
                            )

                    else:

                        c.execute("""
                        UPDATE targets
                        SET last_check=?,
                            fail_count=0
                        WHERE id=?
                        """, (
                            ts,
                            tid
                        ))

                else:

                    new_fail = (
                        t["fail_count"] + 1
                    )

                    if (
                        new_fail >= FAIL_THRESHOLD
                        and t["status"] == "Online"
                    ):

                        c.execute("""
                        UPDATE targets
                        SET status='Offline',
                            last_down=?,
                            fail_count=?,
                            last_check=?
                        WHERE id=?
                        """, (
                            ts,
                            new_fail,
                            ts,
                            tid
                        ))

                        if c.rowcount > 0:

                            c.execute("""
                            INSERT INTO incidents(
                                target,
                                monitor_detail,
                                down_time
                            )
                            VALUES(?,?,?)
                            """, (
                                t["name"],
                                m_info,
                                ts
                            ))

                            conn.commit()

                            send_telegram(
                                t['name'],
                                t['description'],
                                m_info,
                                ts
                            )

                    else:

                        c.execute("""
                        UPDATE targets
                        SET fail_count=?,
                            last_check=?
                        WHERE id=?
                        """, (
                            new_fail,
                            ts,
                            tid
                        ))

                conn.commit()
                conn.close()

                socketio.emit(
                    'status_update'
                )

            except Exception as e:

                print(
                    "MONITOR ERROR:",
                    e
                )

            await asyncio.sleep(
                t["check_interval"]
                if 't' in locals() and t
                else 10
            )

    finally:

        active_monitors.discard(tid)

def send_telegram(host, desc, check, time, duration=None, event_type=None):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID: return
    header = "✅ RECOVERED" if duration else "🚨 ALERT: DOWN/CRITICAL"
    if event_type: msg = f"⚙️ CONFIG: {event_type}\nHost: {host}\nDesc: {desc}\nTime: {time}"
    else: msg = f"{header}\nHost: {host}\nDesc: {desc}\nCheck: {check}\nTime: {time}" + (f"\nDuration: {duration}" if duration else "")
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": msg}, timeout=5)
    except: pass

@app.route("/")
def index():
    if "user" not in session: return redirect("/login")
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        pw = request.form["password"]
        conn = get_db()
        row = conn.execute("SELECT password, role FROM users WHERE username=?", (u,)).fetchone()
        if row and verify_password(row["password"], pw):
            # Transparently upgrade legacy sha256 hashes on successful login.
            if _is_legacy_sha256(row["password"]):
                conn.execute("UPDATE users SET password=? WHERE username=?", (hash_password(pw), u))
                conn.commit()
            conn.close()
            session["user"] = u; session["role"] = row["role"]; return redirect("/")
        conn.close()
    return render_template("login.html")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

@app.route("/status")
@require_login
def status(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM targets")])

@app.route("/incidents")
@require_login
def incidents(): return jsonify([dict(r) for r in get_db().execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 15")])

@app.route("/add", methods=["POST"])
@require_admin
def add():
    p = request.form; ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db(); c = conn.cursor()
    try:
        c.execute("""INSERT INTO targets(name,description,monitor_type,monitor_port,check_interval,timeout,status,last_check,zabbix_item_key,zabbix_host_id) 
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (p["name"], p["description"], p["monitor_type"], p.get("monitor_port", ""), 
                   p["check_interval"], p["timeout"], "Online", ts, p.get("zabbix_item_key", ""), p.get("zabbix_host_id", "")))
        tid = c.lastrowid; conn.commit()
        loop.call_soon_threadsafe(start_task, tid)
        send_telegram(p["name"], p["description"], p["monitor_type"], ts, event_type="ADDED NEW HOST")
        socketio.emit('status_update'); return jsonify({"ok": 1})
    except Exception as e: return jsonify({"ok": 0, "error": str(e)}), 500
    finally: conn.close()

@app.route("/remove/<int:id>", methods=["POST"])
@require_admin
def remove(id):
    conn = get_db(); t = conn.execute("SELECT name, description FROM targets WHERE id=?", (id,)).fetchone()
    conn.execute("DELETE FROM targets WHERE id=?", (id,)); conn.commit(); conn.close()
    if id in tasks:
        tasks[id].cancel()
        del tasks[id]

    if id in task_owners:
        del task_owners[id]
    send_telegram(t['name'], t['description'], None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type="REMOVED HOST")
    socketio.emit('status_update'); return jsonify({"ok": 1})

@app.route("/toggle_maintenance/<int:id>", methods=["POST"])
@require_admin
def maint(id):

    conn = get_db()

    t = conn.execute(
        "SELECT name, description, maintenance FROM targets WHERE id=?",
        (id,)
    ).fetchone()

    new_state = 1 - t['maintenance']

    conn.execute(
        "UPDATE targets SET maintenance=? WHERE id=?",
        (new_state, id)
    )

    conn.commit()
    conn.close()

    # SEND TELEGRAM ALERT
    send_telegram(
        t['name'],
        t['description'],
        "MAINTENANCE",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type=(
            "MAINTENANCE ENABLED"
            if new_state
            else "MAINTENANCE DISABLED"
        )
    )

    socketio.emit('status_update')

    return jsonify({"ok": 1})


@app.route("/update_target/<int:id>", methods=["POST"])
def update_target(id):
    if session.get("role") != "admin": return "Err", 403
    p = request.form
    conn = get_db(); conn.execute("UPDATE targets SET description=?, check_interval=?, timeout=? WHERE id=?", (p["description"], p["check_interval"], p["timeout"], id))
    conn.commit(); conn.close()
    if id in tasks:
        tasks[id].cancel()
        del tasks[id]

    if id in task_owners:
        del task_owners[id]

    loop.call_soon_threadsafe(start_task, id)
    socketio.emit('status_update'); return jsonify({"ok": 1})

@app.route("/clear_incidents", methods=["POST"])
def clear_incidents():
    if session.get("role") != "admin": return "Err", 403
    conn = get_db(); conn.execute("DELETE FROM incidents"); conn.commit(); conn.close()
    socketio.emit('status_update'); return jsonify({"ok": 1})

def start_task(tid):

    # PREVENT DUPLICATE TASKS
    if tid in tasks:

        task = tasks[tid]

        if not task.done():
            return

        del tasks[tid]

    new_task = loop.create_task(
        monitor_target(tid)
    )

    tasks[tid] = new_task
    task_owners[tid] = id(new_task)
def run_loop():
    asyncio.set_event_loop(loop)
    conn = get_db()
    for r in conn.execute("SELECT id FROM targets"): start_task(r["id"])
    conn.close(); loop.run_forever()

if __name__ == "__main__":
    if not MONITOR_STARTED:
        if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
            threading.Thread(target=run_loop, daemon=True).start()
            MONITOR_STARTED = True
    socketio.run(
        app,
        host="0.0.0.0",
        port=5500,
        debug=False,
        allow_unsafe_werkzeug=True
    )
