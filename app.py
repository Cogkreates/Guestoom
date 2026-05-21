"""
Guestoom Analytics v2.1 — Secure Backend
Security: PBKDF2 password hashing, invite-only signup,
          rate limiting, single-use tokens, admin approval flow
"""

import sqlite3, json, hashlib, hmac, os, secrets, csv, io, time
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, make_response

app = Flask(__name__)

DB_PATH   = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "guestoom.db"))
ADMIN_CODE = os.environ.get("ADMIN_CODE", "guestoom-admin-2025").strip()
APP_URL    = os.environ.get("APP_URL", "https://guestoom-production.up.railway.app")

BOT_SIGNATURES = [
    "bot","crawler","spider","scraper","curl","wget","python-requests",
    "go-http","java/","libwww","pingdom","uptimerobot","googlebot",
    "bingbot","yandex","baidu","duckduckbot","slurp","facebookexternalhit",
    "linkedinbot","twitterbot","whatsapp","telegrambot","applebot","headless",
]

def is_bot(ua): return any(s in ua.lower() for s in BOT_SIGNATURES)

# ── CORS ──────────────────────────────────────────────────────────────────────
@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"]      = request.headers.get("Origin","*")
    r.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"]     = "GET,POST,PUT,DELETE,OPTIONS"
    r.headers["Access-Control-Allow-Credentials"] = "true"
    return r

@app.route("/<path:p>", methods=["OPTIONS"])
def opt(p): return "", 204

@app.route("/")
def root(): return jsonify({"product":"Guestoom","status":"ok","version":"2.1.0"})

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    cur = c.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        email      TEXT UNIQUE NOT NULL,
        password   TEXT NOT NULL,
        salt       TEXT NOT NULL,
        api_key    TEXT UNIQUE NOT NULL,
        plan       TEXT DEFAULT 'cloud',
        approved   INTEGER DEFAULT 1,
        created    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS waitlist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        email      TEXT UNIQUE NOT NULL,
        website    TEXT,
        reason     TEXT,
        status     TEXT DEFAULT 'pending',
        created    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS invites (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        email      TEXT NOT NULL,
        token      TEXT UNIQUE NOT NULL,
        used       INTEGER DEFAULT 0,
        expires    TEXT NOT NULL,
        created    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT NOT NULL,
        email      TEXT,
        success    INTEGER DEFAULT 0,
        ts         TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sites (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id  INTEGER,
        domain   TEXT NOT NULL,
        token    TEXT UNIQUE NOT NULL,
        name     TEXT,
        created  TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        site_token       TEXT NOT NULL,
        event_type       TEXT NOT NULL,
        path             TEXT,
        referrer         TEXT,
        referrer_domain  TEXT,
        country          TEXT,
        device           TEXT,
        browser          TEXT,
        os               TEXT,
        session_hash     TEXT,
        duration_seconds INTEGER DEFAULT 0,
        scroll_pct       INTEGER DEFAULT 0,
        element          TEXT,
        click_x_pct      REAL,
        click_y_pct      REAL,
        hour             INTEGER,
        day_of_week      INTEGER,
        is_bounce        INTEGER DEFAULT 0,
        ts               TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS goals (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        site_token TEXT NOT NULL,
        name       TEXT NOT NULL,
        goal_type  TEXT NOT NULL,
        value      TEXT NOT NULL,
        created    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS funnels (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        site_token TEXT NOT NULL,
        name       TEXT NOT NULL,
        steps      TEXT NOT NULL,
        created    TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_ev_token ON events(site_token);
    CREATE INDEX IF NOT EXISTS idx_ev_ts    ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_ev_type  ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_ev_sess  ON events(session_hash);
    CREATE INDEX IF NOT EXISTS idx_inv_token ON invites(token);
    CREATE INDEX IF NOT EXISTS idx_login_ip  ON login_attempts(ip, ts);
    """)
    c.commit()
    c.close()
    print("[Guestoom] Database ready")

# ── Security helpers ──────────────────────────────────────────────────────────
def hash_password(password: str) -> tuple:
    """Returns (hashed, salt) using PBKDF2-HMAC-SHA256 — same security as bcrypt."""
    salt = secrets.token_hex(32)
    key  = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260000  # NIST recommended minimum 2023
    )
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260000
    )
    return hmac.compare_digest(key.hex(), stored_hash)

def get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

def is_rate_limited(ip: str, window_minutes: int = 60, max_attempts: int = 5) -> bool:
    """Block IP if too many failed login attempts in window."""
    db  = get_db()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    count = db.execute(
        "SELECT COUNT(*) n FROM login_attempts WHERE ip=? AND success=0 AND ts>=?",
        (ip, cutoff.isoformat())
    ).fetchone()["n"]
    return count >= max_attempts

def log_attempt(ip: str, email: str, success: bool):
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts(ip,email,success) VALUES(?,?,?)",
        (ip, email, 1 if success else 0)
    )
    db.commit()

def hash_visitor(ip, ua):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(f"{ip}|{ua}|{today}|guestoom-salt".encode()).hexdigest()[:20]

def ip_to_country(ip):
    try:
        import urllib.request
        if ip in ("127.0.0.1","::1",""): return "Local"
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country", timeout=2) as r:
            return json.loads(r.read()).get("country","Unknown")
    except: return "Unknown"

def parse_device(ua):
    u = ua.lower()
    if any(x in u for x in ["iphone","android","mobile"]): return "mobile"
    if any(x in u for x in ["ipad","tablet"]): return "tablet"
    return "desktop"

def parse_browser(ua):
    u = ua.lower()
    for b,k in [("Edge","edg"),("Chrome","chrome"),("Firefox","firefox"),("Safari","safari"),("Opera","opera")]:
        if k in u: return b
    return "Other"

def parse_os(ua):
    u = ua.lower()
    for o,k in [("Windows","windows"),("macOS","mac os"),("Android","android"),("iOS","iphone"),("iOS","ipad"),("Linux","linux")]:
        if k in u: return o
    return "Other"

def ref_domain(ref):
    if not ref: return "Direct"
    try:
        from urllib.parse import urlparse
        h = urlparse(ref).netloc.replace("www.","")
        return h or "Direct"
    except: return "Direct"

def get_site(token): return get_db().execute("SELECT * FROM sites WHERE token=?",(token,)).fetchone()

def require_auth(f):
    @wraps(f)
    def wrap(*a,**kw):
        key  = request.headers.get("Authorization","").replace("Bearer ","").strip()
        user = get_db().execute("SELECT * FROM users WHERE api_key=? AND approved=1",(key,)).fetchone()
        if not user: return jsonify({"error":"Unauthorized"}),401
        g.user = user
        return f(*a,**kw)
    return wrap

def require_admin(f):
    @wraps(f)
    def wrap(*a,**kw):
        code = (request.args.get("code","") or (request.get_json(silent=True) or {}).get("code","")).strip()
        if not hmac.compare_digest(code, ADMIN_CODE):
            return jsonify({"error":"Forbidden"}),403
        return f(*a,**kw)
    return wrap

def owns(token):
    return get_db().execute(
        "SELECT 1 FROM sites WHERE token=? AND user_id=?",(token,g.user["id"])
    ).fetchone()

# ═══════════════════════════════════════════════════════════
# TRACKER  (public)
# ═══════════════════════════════════════════════════════════
@app.route("/track", methods=["POST"])
def track():
    data  = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token or not get_site(token): return jsonify({"ok":False}),401
    ua = request.headers.get("User-Agent","")
    ip = get_client_ip()
    if is_bot(ua): return jsonify({"ok":True,"filtered":"bot"}),200
    ev   = data.get("type","pageview")
    sess = hash_visitor(ip,ua)
    now  = datetime.now(timezone.utc)
    ref  = data.get("referrer","")
    dur  = int(data.get("duration",0))
    bounce = 0
    if ev == "leave":
        pv = get_db().execute(
            "SELECT COUNT(*) n FROM events WHERE session_hash=? AND site_token=? AND event_type=\'pageview\'",
            (sess,token)
        ).fetchone()["n"]
        if pv <= 1 and dur < 10: bounce = 1
    get_db().execute("""
        INSERT INTO events
        (site_token,event_type,path,referrer,referrer_domain,country,
         device,browser,os,session_hash,duration_seconds,scroll_pct,
         element,click_x_pct,click_y_pct,hour,day_of_week,is_bounce)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """,(
        token,ev,data.get("path","/"),ref,ref_domain(ref),
        ip_to_country(ip),parse_device(ua),parse_browser(ua),parse_os(ua),
        sess,dur,int(data.get("scroll_pct",0)),
        data.get("element",""),data.get("cx"),data.get("cy"),
        now.hour,now.weekday(),bounce
    ))
    get_db().commit()
    return jsonify({"ok":True}),200

# ═══════════════════════════════════════════════════════════
# WAITLIST  (public — customers apply for access)
# ═══════════════════════════════════════════════════════════
@app.route("/waitlist", methods=["POST"])
def join_waitlist():
    d    = request.get_json(silent=True) or {}
    name = d.get("name","").strip()
    email= d.get("email","").strip().lower()
    site = d.get("website","").strip()
    why  = d.get("reason","").strip()
    if not name or not email:
        return jsonify({"error":"name and email required"}),400
    try:
        get_db().execute(
            "INSERT INTO waitlist(name,email,website,reason) VALUES(?,?,?,?)",
            (name,email,site,why)
        )
        get_db().commit()
        return jsonify({"ok":True,"message":"Application received. We will review and send your invite within 24 hours."}),201
    except sqlite3.IntegrityError:
        return jsonify({"error":"This email has already applied."}),409

# ═══════════════════════════════════════════════════════════
# ADMIN  (protected by ADMIN_CODE)
# ═══════════════════════════════════════════════════════════
@app.route("/admin/waitlist", methods=["GET"])
@require_admin
def admin_waitlist():
    rows = get_db().execute(
        "SELECT * FROM waitlist ORDER BY created DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/invite", methods=["POST"])
@require_admin
def admin_invite():
    """Approve a waitlist applicant and generate their invite link."""
    d     = request.get_json(silent=True) or {}
    email = d.get("email","").strip().lower()
    if not email: return jsonify({"error":"email required"}),400
    token   = secrets.token_urlsafe(40)
    expires = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
    try:
        get_db().execute(
            "INSERT INTO invites(email,token,expires) VALUES(?,?,?)",
            (email,token,expires)
        )
        get_db().execute(
            "UPDATE waitlist SET status=\'invited\' WHERE email=?",
            (email,)
        )
        get_db().commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"Invite already sent to this email"}),409
    invite_url = f"{APP_URL}/register?token={token}"
    return jsonify({
        "ok":True,
        "email":email,
        "invite_url":invite_url,
        "expires":"48 hours",
        "message":f"Send this link to {email}: {invite_url}"
    }),201

@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_users():
    rows = get_db().execute(
        "SELECT id,email,plan,approved,created FROM users ORDER BY created DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/revoke/<int:uid>", methods=["POST"])
@require_admin
def admin_revoke(uid):
    get_db().execute("UPDATE users SET approved=0 WHERE id=?",(uid,))
    get_db().commit()
    return jsonify({"ok":True,"message":"User access revoked"})

# ═══════════════════════════════════════════════════════════
# AUTH  (invite-only registration + secure login)
# ═══════════════════════════════════════════════════════════
@app.route("/auth/register", methods=["POST"])
def register():
    d      = request.get_json(silent=True) or {}
    email  = d.get("email","").strip().lower()
    pw     = d.get("password","")
    token  = d.get("invite_token","").strip()

    if not email or not pw or not token:
        return jsonify({"error":"email, password, and invite_token required"}),400
    if len(pw) < 8:
        return jsonify({"error":"Password must be at least 8 characters"}),400

    # Validate invite token
    invite = get_db().execute(
        "SELECT * FROM invites WHERE token=? AND used=0",
        (token,)
    ).fetchone()
    if not invite:
        return jsonify({"error":"Invalid or already used invite link"}),401
    if invite["email"].lower() != email:
        return jsonify({"error":"This invite was sent to a different email address"}),401
    # Check expiry
    expires = datetime.fromisoformat(invite["expires"])
    if datetime.now(timezone.utc) > expires:
        return jsonify({"error":"Invite link has expired. Please request a new one."}),401

    pw_hash, salt = hash_password(pw)
    api_key = secrets.token_urlsafe(40)

    try:
        get_db().execute(
            "INSERT INTO users(email,password,salt,api_key) VALUES(?,?,?,?)",
            (email,pw_hash,salt,api_key)
        )
        # Mark invite as used — can never be used again
        get_db().execute("UPDATE invites SET used=1 WHERE token=?",(token,))
        get_db().commit()
        return jsonify({
            "ok":True,
            "api_key":api_key,
            "email":email,
            "warning":"Save your API key now. For security it will not be shown again."
        }),201
    except sqlite3.IntegrityError:
        return jsonify({"error":"An account with this email already exists"}),409

@app.route("/auth/login", methods=["POST"])
def login():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many failed attempts. Try again in 1 hour."}),429

    d     = request.get_json(silent=True) or {}
    email = d.get("email","").strip().lower()
    pw    = d.get("password","")
    if not email or not pw:
        log_attempt(ip,email,False)
        return jsonify({"error":"email and password required"}),400

    user = get_db().execute(
        "SELECT * FROM users WHERE email=? AND approved=1",(email,)
    ).fetchone()

    if not user or not verify_password(pw, user["password"], user["salt"]):
        log_attempt(ip,email,False)
        # Deliberately vague — don\'t reveal whether email exists
        return jsonify({"error":"Invalid email or password"}),401

    log_attempt(ip,email,True)
    return jsonify({
        "ok":True,
        "api_key":user["api_key"],
        "email":user["email"]
    }),200

@app.route("/auth/rotate-key", methods=["POST"])
@require_auth
def rotate_key():
    """Generate a new API key — invalidates the old one immediately."""
    new_key = secrets.token_urlsafe(40)
    get_db().execute("UPDATE users SET api_key=? WHERE id=?",(new_key,g.user["id"]))
    get_db().commit()
    return jsonify({
        "ok":True,
        "api_key":new_key,
        "warning":"Old API key is now invalid. Update all your sites."
    })

# ═══════════════════════════════════════════════════════════
# SITES
# ═══════════════════════════════════════════════════════════
@app.route("/sites", methods=["GET"])
@require_auth
def list_sites():
    rows = get_db().execute(
        "SELECT * FROM sites WHERE user_id=? ORDER BY created DESC",(g.user["id"],)
    ).fetchall()
    out = []
    for r in rows:
        pv   = get_db().execute("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',\'-7 days\')",(r["token"],)).fetchone()["n"]
        live = get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime(\'now\',\'-5 minutes\')",(r["token"],)).fetchone()["n"]
        out.append({**dict(r),"weekly_pageviews":pv,"live_now":live})
    return jsonify(out)

@app.route("/sites", methods=["POST"])
@require_auth
def create_site():
    d      = request.get_json(silent=True) or {}
    domain = d.get("domain","").strip().lower()
    name   = d.get("name",domain)
    if not domain: return jsonify({"error":"domain required"}),400
    token  = secrets.token_urlsafe(24)
    get_db().execute(
        "INSERT INTO sites(user_id,domain,token,name) VALUES(?,?,?,?)",
        (g.user["id"],domain,token,name)
    )
    get_db().commit()
    snippet = f'<script src="{APP_URL}/tracker.js" data-token="{token}" async></script>'
    return jsonify({"domain":domain,"token":token,"name":name,"snippet":snippet}),201

@app.route("/sites/<token>", methods=["DELETE"])
@require_auth
def delete_site(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    get_db().execute("DELETE FROM sites WHERE token=?",(token,))
    get_db().execute("DELETE FROM events WHERE site_token=?",(token,))
    get_db().commit()
    return jsonify({"ok":True})

# ═══════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════
@app.route("/stats/<token>", methods=["GET"])
@require_auth
def stats(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days  = int(request.args.get("days",7))
    since = f"-{days}"
    db    = get_db()
    def q(s,*p):  return db.execute(s,p).fetchall()
    def q1(s,*p): return db.execute(s,p).fetchone()

    tv  = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\')",token,since)["n"]
    tpv = q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\')",token,since)["n"]
    avg = q1("SELECT AVG(duration_seconds) a FROM events WHERE site_token=? AND event_type=\'leave\' AND duration_seconds>0 AND ts>=datetime(\'now\',? || \' days\')",token,since)["a"] or 0
    live= q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime(\'now\',\'-5 minutes\')",token)["n"]
    bnd = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND is_bounce=1 AND ts>=datetime(\'now\',? || \' days\')",token,since)["n"]
    br  = round((bnd/tv*100) if tv else 0,1)
    pv2 = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') AND ts<datetime(\'now\',? || \' days\')",token,f"-{days*2}",since)["n"]
    dv  = round(((tv-pv2)/pv2*100) if pv2 else 0,1)

    durs = q("SELECT duration_seconds FROM events WHERE site_token=? AND event_type=\'leave\' AND duration_seconds>0 AND ts>=datetime(\'now\',? || \' days\')",token,since)
    bkts = {"0-10s":0,"10-30s":0,"30s-1m":0,"1-3m":0,"3-5m":0,"5m+":0}
    for r in durs:
        s=r["duration_seconds"]
        if s<10: bkts["0-10s"]+=1
        elif s<30: bkts["10-30s"]+=1
        elif s<60: bkts["30s-1m"]+=1
        elif s<180: bkts["1-3m"]+=1
        elif s<300: bkts["3-5m"]+=1
        else: bkts["5m+"]+=1

    scrls = q("SELECT scroll_pct FROM events WHERE site_token=? AND event_type=\'leave\' AND scroll_pct>0 AND ts>=datetime(\'now\',? || \' days\')",token,since)
    sbkts = {"0-25%":0,"25-50%":0,"50-75%":0,"75-100%":0}
    for r in scrls:
        p=r["scroll_pct"]
        if p<=25: sbkts["0-25%"]+=1
        elif p<=50: sbkts["25-50%"]+=1
        elif p<=75: sbkts["50-75%"]+=1
        else: sbkts["75-100%"]+=1

    goals_raw = db.execute("SELECT * FROM goals WHERE site_token=?",(token,)).fetchall()
    goals_out = []
    for gr in goals_raw:
        if gr["goal_type"]=="path":
            conv=q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime(\'now\',? || \' days\')",token,gr["value"],since)["n"]
        else:
            conv=q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type=\'click\' AND element=? AND ts>=datetime(\'now\',? || \' days\')",token,gr["value"],since)["n"]
        goals_out.append({"id":gr["id"],"name":gr["name"],"type":gr["goal_type"],"value":gr["value"],"conversions":conv,"rate":round((conv/tv*100) if tv else 0,2)})

    return jsonify({
        "summary":{"total_visitors":tv,"total_pageviews":tpv,"avg_session_seconds":round(avg),"live_now":live,"bounce_rate":br,"delta_visitors":dv},
        "by_day":         [dict(r) for r in q("SELECT DATE(ts) day,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY day ORDER BY day",token,since)],
        "countries":      [dict(r) for r in q("SELECT country,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY country ORDER BY visits DESC LIMIT 10",token,since)],
        "hourly":         [dict(r) for r in q("SELECT hour,COUNT(*) visits FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY hour ORDER BY hour",token,since)],
        "top_pages":      [dict(r) for r in q("SELECT path,COUNT(*) views,COUNT(DISTINCT session_hash) uniq FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY path ORDER BY views DESC LIMIT 10",token,since)],
        "referrers":      [dict(r) for r in q("SELECT referrer_domain src,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY referrer_domain ORDER BY visits DESC LIMIT 10",token,since)],
        "devices":        [dict(r) for r in q("SELECT device,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY device",token,since)],
        "browsers":       [dict(r) for r in q("SELECT browser,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY browser ORDER BY n DESC LIMIT 6",token,since)],
        "oses":           [dict(r) for r in q("SELECT os,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type=\'pageview\' AND ts>=datetime(\'now\',? || \' days\') GROUP BY os ORDER BY n DESC LIMIT 6",token,since)],
        "session_buckets":[{"range":k,"count":v} for k,v in bkts.items()],
        "scroll_buckets": [{"range":k,"count":v} for k,v in sbkts.items()],
        "top_elements":   [dict(r) for r in q("SELECT element,COUNT(*) clicks FROM events WHERE site_token=? AND event_type=\'click\' AND element!=\'\'  AND ts>=datetime(\'now\',? || \' days\') GROUP BY element ORDER BY clicks DESC LIMIT 10",token,since)],
        "goals":          goals_out,
    })

# ═══════════════════════════════════════════════════════════
# HEATMAP
# ═══════════════════════════════════════════════════════════
@app.route("/heatmap/<token>", methods=["GET"])
@require_auth
def heatmap(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    path = request.args.get("path","/")
    days = int(request.args.get("days",7))
    rows = get_db().execute("""
        SELECT ROUND(click_x_pct,1) x, ROUND(click_y_pct,1) y, COUNT(*) weight
        FROM events WHERE site_token=? AND event_type=\'click\'
          AND path=? AND click_x_pct IS NOT NULL
          AND ts>=datetime(\'now\',? || \' days\')
        GROUP BY ROUND(click_x_pct,1), ROUND(click_y_pct,1)
    """,(token,path,f"-{days}")).fetchall()
    return jsonify({"path":path,"points":[dict(r) for r in rows]})

# ═══════════════════════════════════════════════════════════
# FUNNELS
# ═══════════════════════════════════════════════════════════
@app.route("/funnels/<token>", methods=["GET"])
@require_auth
def list_funnels(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    return jsonify([dict(r) for r in get_db().execute("SELECT * FROM funnels WHERE site_token=?",(token,)).fetchall()])

@app.route("/funnels/<token>", methods=["POST"])
@require_auth
def create_funnel(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    d = request.get_json(silent=True) or {}
    get_db().execute("INSERT INTO funnels(site_token,name,steps) VALUES(?,?,?)",(token,d.get("name","Funnel"),json.dumps(d.get("steps",[]))))
    get_db().commit()
    return jsonify({"ok":True}),201

@app.route("/funnels/<token>/<int:fid>/stats", methods=["GET"])
@require_auth
def funnel_stats(token,fid):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days = int(request.args.get("days",7))
    fn   = get_db().execute("SELECT * FROM funnels WHERE id=? AND site_token=?",(fid,token)).fetchone()
    if not fn: return jsonify({"error":"Not found"}),404
    steps=json.loads(fn["steps"])
    out,prev=[],None
    for i,path in enumerate(steps):
        n=get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime(\'now\',? || \' days\')",(token,path,f"-{days}")).fetchone()["n"]
        drop=round(((prev-n)/prev*100) if prev and prev>0 else 0,1)
        out.append({"step":i+1,"path":path,"sessions":n,"drop_pct":drop})
        prev=n
    return jsonify({"funnel":fn["name"],"steps":out})

# ═══════════════════════════════════════════════════════════
# GOALS
# ═══════════════════════════════════════════════════════════
@app.route("/goals/<token>", methods=["POST"])
@require_auth
def create_goal(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    d=request.get_json(silent=True) or {}
    get_db().execute("INSERT INTO goals(site_token,name,goal_type,value) VALUES(?,?,?,?)",(token,d.get("name","Goal"),d.get("type","path"),d.get("value","/")))
    get_db().commit()
    return jsonify({"ok":True}),201

@app.route("/goals/<token>/<int:gid>", methods=["DELETE"])
@require_auth
def delete_goal(token,gid):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    get_db().execute("DELETE FROM goals WHERE id=? AND site_token=?",(gid,token))
    get_db().commit()
    return jsonify({"ok":True})

# ═══════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════
@app.route("/export/<token>", methods=["GET"])
@require_auth
def export_csv(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days=int(request.args.get("days",30))
    rows=get_db().execute("""
        SELECT event_type,path,country,device,browser,os,referrer_domain,
               duration_seconds,scroll_pct,element,hour,ts
        FROM events WHERE site_token=? AND ts>=datetime(\'now\',? || \' days\')
        ORDER BY ts DESC LIMIT 100000
    """,(token,f"-{days}")).fetchall()
    out=io.StringIO()
    w=csv.writer(out)
    w.writerow(["type","path","country","device","browser","os","referrer","duration_s","scroll_pct","element","hour","timestamp"])
    for r in rows: w.writerow(list(r))
    resp=make_response(out.getvalue())
    resp.headers["Content-Type"]="text/csv"
    resp.headers["Content-Disposition"]=f"attachment; filename=guestoom-{token[:8]}.csv"
    return resp

# ═══════════════════════════════════════════════════════════
# ADMIN PANEL  (protected by ADMIN_CODE env var)
# ═══════════════════════════════════════════════════════════
@app.route("/admin")
def admin_panel():
    code = request.args.get("code","").strip()
    if not hmac.compare_digest(code, ADMIN_CODE):
        return "<h2 style='font-family:sans-serif;color:#ff4d6d;padding:40px'>Access Denied</h2>", 403

    # Handle form submissions
    msg = ""
    msg_type = ""

    if request.args.get("action") == "invite":
        email = request.args.get("email","").strip().lower()
        if email:
            token = secrets.token_urlsafe(40)
            expires = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
            try:
                get_db().execute("INSERT INTO invites(email,token,expires) VALUES(?,?,?)",(email,token,expires))
                get_db().execute("UPDATE waitlist SET status='invited' WHERE email=?",(email,))
                get_db().commit()
                invite_url = f"{APP_URL}/register?token={token}"
                msg = f"Invite created for {email} | Link: {invite_url}"
                msg_type = "ok"
            except sqlite3.IntegrityError:
                msg = "Invite already sent to this email"
                msg_type = "err"
        else:
            msg = "Enter an email address"
            msg_type = "err"

    if request.args.get("action") == "revoke":
        uid = request.args.get("uid","")
        if uid:
            get_db().execute("UPDATE users SET approved=0 WHERE id=?",(uid,))
            get_db().commit()
            msg = f"User {uid} access revoked"
            msg_type = "ok"

    # Load data
    waitlist = get_db().execute("SELECT * FROM waitlist ORDER BY created DESC").fetchall()
    users    = get_db().execute("SELECT id,email,plan,approved,created FROM users ORDER BY created DESC").fetchall()

    msg_html = ""
    if msg:
        bg  = "#00e5a012" if msg_type=="ok" else "#ff4d6d12"
        bdr = "#00e5a033" if msg_type=="ok" else "#ff4d6d33"
        col = "#dde3f0"   if msg_type=="ok" else "#ff4d6d"
        msg_html = f'<div style="background:{bg};border:1px solid {bdr};border-radius:8px;padding:14px;margin-bottom:20px;font-size:13px;color:{col};word-break:break-all">{msg}</div>'

    wl_rows = ""
    for w in waitlist:
        wl_rows += f"""<tr>
            <td>{w['name']}</td>
            <td>{w['email']}</td>
            <td>{w['website'] or '-'}</td>
            <td>{w['reason'] or '-'}</td>
            <td><span style="font-size:10px;padding:2px 8px;border-radius:20px;background:#ffa04018;border:1px solid #ffa04033;color:#ffa040">{w['status']}</span></td>
            <td><a href="/admin?code={code}&action=invite&email={w['email']}" style="color:#b8f04a;font-size:11px;text-decoration:none;border:1px solid #b8f04a33;padding:3px 8px;border-radius:4px">Invite</a></td>
        </tr>"""

    user_rows = ""
    for u in users:
        status_col = "#00e5a0" if u['approved'] else "#ff4d6d"
        status_txt = "active" if u['approved'] else "revoked"
        uid_val = u['id']
        revoke_btn = (f'<a href="/admin?code={code}&action=revoke&uid={uid_val}" style="color:#ff4d6d;font-size:11px;text-decoration:none;border:1px solid #ff4d6d33;padding:3px 8px;border-radius:4px">Revoke</a>') if u['approved'] else '-'
        user_rows += f"""<tr>
            <td>{u['id']}</td>
            <td>{u['email']}</td>
            <td>{u['plan']}</td>
            <td><span style="color:{status_col};font-size:11px">{status_txt}</span></td>
            <td>{u['created'][:10]}</td>
            <td>{revoke_btn}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Guestoom Admin</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#07080f;color:#dde3f0;font-family:Arial,sans-serif;padding:20px 16px}}
h1{{font-size:20px;color:#b8f04a;margin-bottom:4px}}
.sub{{color:#4a5270;font-size:12px;margin-bottom:24px}}
.card{{background:#0e0f1a;border:1px solid #1c1f35;border-radius:12px;padding:20px;margin-bottom:16px}}
h2{{font-size:13px;color:#dde3f0;margin-bottom:14px}}
label{{display:block;font-size:10px;color:#4a5270;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px;margin-top:12px}}
input{{width:100%;padding:10px 12px;background:#13172a;border:1px solid #1c1f35;border-radius:8px;color:#dde3f0;font-size:13px;outline:none;box-sizing:border-box}}
.btn{{display:inline-block;margin-top:14px;width:100%;padding:11px;background:#b8f04a;border:none;border-radius:8px;color:#07080f;font-size:13px;font-weight:700;cursor:pointer;text-align:center;text-decoration:none}}
table{{width:100%;border-collapse:collapse;font-size:11px;margin-top:8px}}
th{{text-align:left;color:#4a5270;font-size:9px;letter-spacing:.08em;text-transform:uppercase;padding:8px 6px;border-bottom:1px solid #1c1f35}}
td{{padding:8px 6px;border-bottom:1px solid #1c1f35;color:#dde3f0;word-break:break-all}}
.empty{{color:#4a5270;font-size:12px;padding:12px 0}}
</style>
</head>
<body>
<h1>Guestoom Admin</h1>
<p class="sub">Manage waitlist and send invites.</p>

{msg_html}

<div class="card">
  <h2>Send Invite</h2>
  <p style="color:#4a5270;font-size:12px;margin-bottom:12px">Enter email to generate a 48-hour invite link.</p>
  <form method="GET" action="/admin">
    <input type="hidden" name="code" value="{code}"/>
    <input type="hidden" name="action" value="invite"/>
    <label>Email Address</label>
    <input type="email" name="email" placeholder="customer@email.com" required/>
    <button type="submit" class="btn">Send Invite</button>
  </form>
</div>

<div class="card">
  <h2>Waitlist ({len(waitlist)} applications)</h2>
  {'<table><tr><th>Name</th><th>Email</th><th>Website</th><th>Reason</th><th>Status</th><th>Action</th></tr>' + wl_rows + '</table>' if waitlist else '<p class="empty">No applications yet.</p>'}
</div>

<div class="card">
  <h2>Users ({len(users)} accounts)</h2>
  {'<table><tr><th>ID</th><th>Email</th><th>Plan</th><th>Status</th><th>Joined</th><th>Action</th></tr>' + user_rows + '</table>' if users else '<p class="empty">No users yet.</p>'}
</div>

</body></html>"""


@app.route("/register", methods=["GET","POST"])
def register_page():
    token = request.args.get("token","")
    if not token:
        return "<h2 style='font-family:sans-serif;color:#ff4d6d;padding:40px'>Invalid invite link.</h2>", 400

    invite = get_db().execute(
        "SELECT * FROM invites WHERE token=? AND used=0",(token,)
    ).fetchone()
    if not invite:
        return "<h2 style='font-family:sans-serif;padding:40px;color:#ff4d6d'>This invite link has already been used or does not exist.</h2>", 400
    expires = datetime.fromisoformat(invite["expires"])
    if datetime.now(timezone.utc) > expires:
        return "<h2 style='font-family:sans-serif;padding:40px;color:#ff4d6d'>This invite link has expired. Contact support for a new one.</h2>", 400

    msg = ""
    msg_type = ""
    api_key_display = ""

    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pw    = request.form.get("password","")
        pw2   = request.form.get("password2","")
        if len(pw) < 8:
            msg = "Password must be at least 8 characters"
            msg_type = "err"
        elif pw != pw2:
            msg = "Passwords do not match"
            msg_type = "err"
        elif email != invite["email"].lower():
            msg = "Email does not match the invite"
            msg_type = "err"
        else:
            pw_hash, salt = hash_password(pw)
            api_key = secrets.token_urlsafe(40)
            try:
                get_db().execute(
                    "INSERT INTO users(email,password,salt,api_key) VALUES(?,?,?,?)",
                    (email,pw_hash,salt,api_key)
                )
                get_db().execute("UPDATE invites SET used=1 WHERE token=?",(token,))
                get_db().commit()
                api_key_display = api_key
                msg = "Account created successfully!"
                msg_type = "ok"
            except sqlite3.IntegrityError:
                msg = "An account with this email already exists"
                msg_type = "err"

    msg_html = ""
    if msg and msg_type == "err":
        msg_html = f'<div style="background:#ff4d6d12;border:1px solid #ff4d6d33;border-radius:8px;padding:12px;margin-bottom:16px;font-size:13px;color:#ff4d6d">{msg}</div>'

    if api_key_display:
        return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Account Created</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{background:#07080f;color:#dde3f0;font-family:Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.box{{width:100%;max-width:420px}}.card{{background:#0e0f1a;border:1px solid #1c1f35;border-radius:12px;padding:28px}}h1{{font-size:20px;color:#b8f04a;margin-bottom:16px}}.key{{background:#07080f;border:1px solid #b8f04a33;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#b8f04a;word-break:break-all;margin:12px 0}}.warn{{background:#ffa04012;border:1px solid #ffa04033;border-radius:8px;padding:12px;font-size:12px;color:#ffa040;margin-top:12px}}</style>
</head><body>
<div class="box">
<div class="card">
<h1>Account Created!</h1>
<p style="font-size:13px;color:#4a5270;margin-bottom:16px">Welcome to Guestoom. Your API key is below.</p>
<p style="font-size:11px;color:#4a5270;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">Your API Key</p>
<div class="key">{api_key_display}</div>
<div class="warn">Save this key now — it will not be shown again. You need it to log into your dashboard.</div>
</div>
</div>
</body></html>"""

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Create Your Guestoom Account</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#07080f;color:#dde3f0;font-family:Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.box{{width:100%;max-width:420px}}
h1{{font-size:22px;color:#b8f04a;margin-bottom:4px;text-align:center}}
.sub{{color:#4a5270;font-size:13px;margin-bottom:24px;text-align:center}}
.card{{background:#0e0f1a;border:1px solid #1c1f35;border-radius:12px;padding:28px}}
label{{display:block;font-size:10px;color:#4a5270;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px;margin-top:14px}}
input{{width:100%;padding:10px 12px;background:#13172a;border:1px solid #1c1f35;border-radius:8px;color:#dde3f0;font-size:14px;outline:none;box-sizing:border-box}}
.btn{{margin-top:20px;width:100%;padding:13px;background:#b8f04a;border:none;border-radius:8px;color:#07080f;font-size:14px;font-weight:700;cursor:pointer}}
.badge{{background:#b8f04a18;border:1px solid #b8f04a33;border-radius:8px;padding:10px 14px;font-size:12px;color:#b8f04a;margin-bottom:16px;text-align:center}}
</style>
</head>
<body>
<div class="box">
  <h1>Guestoom</h1>
  <p class="sub">You have been invited. Create your account.</p>
  <div class="card">
    {msg_html}
    <div class="badge">Invite for: {invite["email"]}</div>
    <form method="POST" action="/register?token={token}">
      <label>Email</label>
      <input type="email" name="email" value="{invite["email"]}" readonly style="opacity:0.6"/>
      <label>Password (min 8 characters)</label>
      <input type="password" name="password" placeholder="choose a strong password" required/>
      <label>Confirm Password</label>
      <input type="password" name="password2" placeholder="repeat your password" required/>
      <button type="submit" class="btn">Create Account</button>
    </form>
  </div>
</div>
</body></html>"""

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Create Your Guestoom Account</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#07080f;color:#dde3f0;font-family:Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.box{{width:100%;max-width:420px}}
h1{{font-size:22px;color:#b8f04a;margin-bottom:4px;text-align:center}}
.sub{{color:#4a5270;font-size:13px;margin-bottom:28px;text-align:center}}
.card{{background:#0e0f1a;border:1px solid #1c1f35;border-radius:12px;padding:28px}}
label{{display:block;font-size:10px;color:#4a5270;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px;margin-top:14px}}
input{{width:100%;padding:10px 12px;background:#13172a;border:1px solid #1c1f35;border-radius:8px;color:#dde3f0;font-size:14px;outline:none;box-sizing:border-box}}
.btn{{margin-top:20px;width:100%;padding:13px;background:#b8f04a;border:none;border-radius:8px;color:#07080f;font-size:14px;font-weight:700;cursor:pointer}}
.result{{margin-top:14px;padding:14px;border-radius:8px;font-size:13px;display:none;line-height:1.8;word-break:break-all}}
.ok{{background:#00e5a012;border:1px solid #00e5a033}}
.err{{background:#ff4d6d12;border:1px solid #ff4d6d33;color:#ff4d6d}}
.hl{{color:#b8f04a;font-weight:700;word-break:break-all}}
.muted{{color:#4a5270;font-size:11px}}
.invite-badge{{background:#b8f04a18;border:1px solid #b8f04a33;border-radius:8px;padding:10px 14px;font-size:12px;color:#b8f04a;margin-bottom:20px;text-align:center}}
</style>
</head>
<body>
<div class="box">
  <h1>Guestoom</h1>
  <p class="sub">You have been invited. Create your account below.</p>
  <div class="card">
    <div class="invite-badge">Invite for: {invite["email"]}</div>
    <label>Email</label>
    <input id="email" type="email" value="{invite["email"]}" readonly style="opacity:0.6"/>
    <label>Password (min 8 characters)</label>
    <input id="pw" type="password" placeholder="choose a strong password"/>
    <label>Confirm Password</label>
    <input id="pw2" type="password" placeholder="repeat your password"/>
    <button class="btn" onclick="createAccount()">Create Account</button>
    <div class="result" id="res"></div>
  </div>
</div>
<script>
async function createAccount(){{
  var email=document.getElementById("email").value;
  var pw=document.getElementById("pw").value;
  var pw2=document.getElementById("pw2").value;
  var res=document.getElementById("res");
  if(pw.length<8){{res.innerHTML="Password must be at least 8 characters";res.className="result err";res.style.display="block";return;}}
  if(pw!==pw2){{res.innerHTML="Passwords do not match";res.className="result err";res.style.display="block";return;}}
  res.innerHTML="Creating account...";res.className="result ok";res.style.display="block";
  try{{
    var r=await fetch("/auth/register",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{email:email,password:pw,invite_token:"{token}"}})}});
    var d=await r.json();
    if(d.ok){{
      res.innerHTML="Account created!<br><br>Your API Key:<br><span class=\"hl\">"+d.api_key+"</span><br><br><span class=\"muted\">Save this key now. It will not be shown again. Paste it into your Guestoom dashboard to log in.</span>";
      res.className="result ok";
    }}else{{res.innerHTML=d.error||JSON.stringify(d);res.className="result err";}}
  }}catch(e){{res.innerHTML=e.message;res.className="result err";}}
}}
</script>
</body></html>"""

@app.route("/health")
def health(): return jsonify({"status":"ok","product":"Guestoom","version":"2.1.0"})

# ── Run init_db always — works with both gunicorn and direct python ──
init_db()

if __name__ == "__main__":
    print("[Guestoom] Server on http://localhost:5000")
    app.run(debug=True,host="0.0.0.0",port=5000)
