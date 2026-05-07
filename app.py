"""
Guestoom Analytics — Complete Backend v2.0
Features: heatmap, scroll depth, funnels, goals, user auth, CSV export,
          bot filtering, multi-site, referrers, devices, bounce rate
"""

import sqlite3, json, hashlib, os, secrets, csv, io
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, g, make_response

app = Flask(__name__)

# Railway stores ephemeral files in /tmp — use env var to override in production
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "guestoom.db"))

BOT_SIGNATURES = [
    "bot","crawler","spider","scraper","curl","wget","python-requests",
    "go-http","java/","libwww","pingdom","uptimerobot","googlebot",
    "bingbot","yandex","baidu","duckduckbot","slurp","facebookexternalhit",
    "linkedinbot","twitterbot","whatsapp","telegrambot","applebot","headless",
]

def is_bot(ua):
    u = ua.lower()
    return any(s in u for s in BOT_SIGNATURES)

# ── CORS ──────────────────────────────────────────────────────────────────────
@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"]  = request.headers.get("Origin","*")
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    r.headers["Access-Control-Allow-Credentials"] = "true"
    return r

@app.route("/<path:p>", methods=["OPTIONS"])
def opt(p): return "", 204

@app.route("/")
def root(): return jsonify({"product": "Guestoom", "status": "ok", "version": "2.0.0"})

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db",None)
    if db: db.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    cur = c.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        email    TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        api_key  TEXT UNIQUE NOT NULL,
        plan     TEXT DEFAULT 'free',
        created  TEXT DEFAULT CURRENT_TIMESTAMP
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
    """)
    c.commit()
    c.close()
    print("[Guestoom] ✓ Database ready")

# ── Helpers ───────────────────────────────────────────────────────────────────
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

def get_site(token):
    return get_db().execute("SELECT * FROM sites WHERE token=?",(token,)).fetchone()

def require_auth(f):
    @wraps(f)
    def wrap(*a,**kw):
        key = request.headers.get("Authorization","").replace("Bearer ","")
        user = get_db().execute("SELECT * FROM users WHERE api_key=?",(key,)).fetchone()
        if not user: return jsonify({"error":"Unauthorized"}),401
        g.user = user
        return f(*a,**kw)
    return wrap

def owns(token):
    return get_db().execute(
        "SELECT 1 FROM sites WHERE token=? AND user_id=?",(token,g.user["id"])
    ).fetchone()

# ═════════════════════════════════════════════════════════════════════════════
# TRACKER  (public endpoint — called by embedded script)
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/track", methods=["POST"])
def track():
    data  = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token or not get_site(token):
        return jsonify({"ok":False}),401

    ua = request.headers.get("User-Agent","")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if is_bot(ua):
        return jsonify({"ok":True,"filtered":"bot"}),200

    ev   = data.get("type","pageview")
    sess = hash_visitor(ip, ua)
    now  = datetime.now(timezone.utc)
    ref  = data.get("referrer","")
    dur  = int(data.get("duration",0))

    # Bounce detection
    bounce = 0
    if ev == "leave":
        pv = get_db().execute(
            "SELECT COUNT(*) n FROM events WHERE session_hash=? AND site_token=? AND event_type='pageview'",
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
        token, ev,
        data.get("path","/"), ref, ref_domain(ref),
        ip_to_country(ip), parse_device(ua), parse_browser(ua), parse_os(ua),
        sess, dur,
        int(data.get("scroll_pct",0)),
        data.get("element",""),
        data.get("cx"), data.get("cy"),
        now.hour, now.weekday(), bounce
    ))
    get_db().commit()
    return jsonify({"ok":True}),200

# ═════════════════════════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/auth/register", methods=["POST"])
def register():
    d  = request.get_json(silent=True) or {}
    em = d.get("email","").strip().lower()
    pw = d.get("password","")
    if not em or not pw: return jsonify({"error":"email and password required"}),400
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    api_key = secrets.token_urlsafe(32)
    try:
        get_db().execute("INSERT INTO users(email,password,api_key) VALUES(?,?,?)",(em,pw_hash,api_key))
        get_db().commit()
        return jsonify({"api_key":api_key,"email":em}),201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email already registered"}),409

@app.route("/auth/login", methods=["POST"])
def login():
    d  = request.get_json(silent=True) or {}
    em = d.get("email","").strip().lower()
    pw = hashlib.sha256(d.get("password","").encode()).hexdigest()
    u  = get_db().execute("SELECT * FROM users WHERE email=? AND password=?",(em,pw)).fetchone()
    if not u: return jsonify({"error":"Invalid credentials"}),401
    return jsonify({"api_key":u["api_key"],"email":u["email"],"id":u["id"]}),200

# ═════════════════════════════════════════════════════════════════════════════
# SITES
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/sites", methods=["GET"])
@require_auth
def list_sites():
    rows = get_db().execute("SELECT * FROM sites WHERE user_id=? ORDER BY created DESC",(g.user["id"],)).fetchall()
    out = []
    for r in rows:
        pv   = get_db().execute("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now','-7 days')",(r["token"],)).fetchone()["n"]
        live = get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime('now','-5 minutes')",(r["token"],)).fetchone()["n"]
        out.append({**dict(r),"weekly_pageviews":pv,"live_now":live})
    return jsonify(out)

@app.route("/sites", methods=["POST"])
@require_auth
def create_site():
    d      = request.get_json(silent=True) or {}
    domain = d.get("domain","").strip().lower()
    name   = d.get("name", domain)
    if not domain: return jsonify({"error":"domain required"}),400
    token  = secrets.token_urlsafe(24)
    get_db().execute("INSERT INTO sites(user_id,domain,token,name) VALUES(?,?,?,?)",(g.user["id"],domain,token,name))
    get_db().commit()
    snippet = f'<script src="https://cdn.guestoom.com/tracker.js" data-token="{token}" async></script>'
    return jsonify({"domain":domain,"token":token,"name":name,"snippet":snippet}),201

@app.route("/sites/<token>", methods=["DELETE"])
@require_auth
def delete_site(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    get_db().execute("DELETE FROM sites WHERE token=?",(token,))
    get_db().execute("DELETE FROM events WHERE site_token=?",(token,))
    get_db().commit()
    return jsonify({"ok":True})

# ═════════════════════════════════════════════════════════════════════════════
# STATS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/stats/<token>", methods=["GET"])
@require_auth
def stats(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days  = int(request.args.get("days",7))
    since = f"-{days}"
    db    = get_db()
    def q(s,*p):  return db.execute(s,p).fetchall()
    def q1(s,*p): return db.execute(s,p).fetchone()

    tv  = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days')",token,since)["n"]
    tpv = q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days')",token,since)["n"]
    avg = q1("SELECT AVG(duration_seconds) a FROM events WHERE site_token=? AND event_type='leave' AND duration_seconds>0 AND ts>=datetime('now',? || ' days')",token,since)["a"] or 0
    live= q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime('now','-5 minutes')",token)["n"]
    bnd = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND is_bounce=1 AND ts>=datetime('now',? || ' days')",token,since)["n"]
    br  = round((bnd/tv*100) if tv else 0,1)
    pv2 = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') AND ts<datetime('now',? || ' days')",token,f"-{days*2}",since)["n"]
    dv  = round(((tv-pv2)/pv2*100) if pv2 else 0,1)

    # Duration buckets
    durs = q("SELECT duration_seconds FROM events WHERE site_token=? AND event_type='leave' AND duration_seconds>0 AND ts>=datetime('now',? || ' days')",token,since)
    bkts = {"0-10s":0,"10-30s":0,"30s-1m":0,"1-3m":0,"3-5m":0,"5m+":0}
    for r in durs:
        s=r["duration_seconds"]
        if s<10: bkts["0-10s"]+=1
        elif s<30: bkts["10-30s"]+=1
        elif s<60: bkts["30s-1m"]+=1
        elif s<180: bkts["1-3m"]+=1
        elif s<300: bkts["3-5m"]+=1
        else: bkts["5m+"]+=1

    # Scroll buckets
    scrls = q("SELECT scroll_pct FROM events WHERE site_token=? AND event_type='leave' AND scroll_pct>0 AND ts>=datetime('now',? || ' days')",token,since)
    sbkts = {"0-25%":0,"25-50%":0,"50-75%":0,"75-100%":0}
    for r in scrls:
        p=r["scroll_pct"]
        if p<=25: sbkts["0-25%"]+=1
        elif p<=50: sbkts["25-50%"]+=1
        elif p<=75: sbkts["50-75%"]+=1
        else: sbkts["75-100%"]+=1

    # Goals
    goals_raw = db.execute("SELECT * FROM goals WHERE site_token=?",(token,)).fetchall()
    goals_out = []
    for gr in goals_raw:
        if gr["goal_type"]=="path":
            conv=q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime('now',? || ' days')",token,gr["value"],since)["n"]
        else:
            conv=q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='click' AND element=? AND ts>=datetime('now',? || ' days')",token,gr["value"],since)["n"]
        goals_out.append({"id":gr["id"],"name":gr["name"],"type":gr["goal_type"],"value":gr["value"],"conversions":conv,"rate":round((conv/tv*100) if tv else 0,2)})

    return jsonify({
        "summary":{"total_visitors":tv,"total_pageviews":tpv,"avg_session_seconds":round(avg),"live_now":live,"bounce_rate":br,"delta_visitors":dv},
        "by_day":          [dict(r) for r in q("SELECT DATE(ts) day,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY day ORDER BY day",token,since)],
        "countries":       [dict(r) for r in q("SELECT country,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY country ORDER BY visits DESC LIMIT 10",token,since)],
        "hourly":          [dict(r) for r in q("SELECT hour,COUNT(*) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY hour ORDER BY hour",token,since)],
        "top_pages":       [dict(r) for r in q("SELECT path,COUNT(*) views,COUNT(DISTINCT session_hash) uniq FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY path ORDER BY views DESC LIMIT 10",token,since)],
        "referrers":       [dict(r) for r in q("SELECT referrer_domain src,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY referrer_domain ORDER BY visits DESC LIMIT 10",token,since)],
        "devices":         [dict(r) for r in q("SELECT device,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY device",token,since)],
        "browsers":        [dict(r) for r in q("SELECT browser,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY browser ORDER BY n DESC LIMIT 6",token,since)],
        "oses":            [dict(r) for r in q("SELECT os,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY os ORDER BY n DESC LIMIT 6",token,since)],
        "session_buckets": [{"range":k,"count":v} for k,v in bkts.items()],
        "scroll_buckets":  [{"range":k,"count":v} for k,v in sbkts.items()],
        "top_elements":    [dict(r) for r in q("SELECT element,COUNT(*) clicks FROM events WHERE site_token=? AND event_type='click' AND element!='' AND ts>=datetime('now',? || ' days') GROUP BY element ORDER BY clicks DESC LIMIT 10",token,since)],
        "goals":           goals_out,
    })

# ═════════════════════════════════════════════════════════════════════════════
# HEATMAP
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/heatmap/<token>", methods=["GET"])
@require_auth
def heatmap(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    path = request.args.get("path","/")
    days = int(request.args.get("days",7))
    rows = get_db().execute("""
        SELECT ROUND(click_x_pct,1) x, ROUND(click_y_pct,1) y, COUNT(*) weight
        FROM events WHERE site_token=? AND event_type='click'
          AND path=? AND click_x_pct IS NOT NULL
          AND ts>=datetime('now',? || ' days')
        GROUP BY ROUND(click_x_pct,1), ROUND(click_y_pct,1)
    """,(token,path,f"-{days}")).fetchall()
    return jsonify({"path":path,"points":[dict(r) for r in rows]})

# ═════════════════════════════════════════════════════════════════════════════
# FUNNELS
# ═════════════════════════════════════════════════════════════════════════════
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
def funnel_stats(token, fid):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days = int(request.args.get("days",7))
    fn   = get_db().execute("SELECT * FROM funnels WHERE id=? AND site_token=?",(fid,token)).fetchone()
    if not fn: return jsonify({"error":"Not found"}),404
    steps = json.loads(fn["steps"])
    out, prev = [], None
    for i,path in enumerate(steps):
        n = get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime('now',? || ' days')",(token,path,f"-{days}")).fetchone()["n"]
        drop = round(((prev-n)/prev*100) if prev and prev>0 else 0,1)
        out.append({"step":i+1,"path":path,"sessions":n,"drop_pct":drop})
        prev = n
    return jsonify({"funnel":fn["name"],"steps":out})

# ═════════════════════════════════════════════════════════════════════════════
# GOALS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/goals/<token>", methods=["POST"])
@require_auth
def create_goal(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    d = request.get_json(silent=True) or {}
    get_db().execute("INSERT INTO goals(site_token,name,goal_ty@app.route("/",defaults={"p":""},methods=["OPTIONS"])
@app.route("/<path:p>",methods=["OPTIONS"])
def opt(p): return "",204

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db",None)
    if db: db.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    cur = c.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        email    TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        api_key  TEXT UNIQUE NOT NULL,
        plan     TEXT DEFAULT 'free',
        created  TEXT DEFAULT CURRENT_TIMESTAMP
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
    """)
    c.commit()
    c.close()
    print("[Guestoom] ✓ Database ready")

# ── Helpers ───────────────────────────────────────────────────────────────────
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

def get_site(token):
    return get_db().execute("SELECT * FROM sites WHERE token=?",(token,)).fetchone()

def require_auth(f):
    @wraps(f)
    def wrap(*a,**kw):
        key = request.headers.get("Authorization","").replace("Bearer ","")
        user = get_db().execute("SELECT * FROM users WHERE api_key=?",(key,)).fetchone()
        if not user: return jsonify({"error":"Unauthorized"}),401
        g.user = user
        return f(*a,**kw)
    return wrap

def owns(token):
    return get_db().execute(
        "SELECT 1 FROM sites WHERE token=? AND user_id=?",(token,g.user["id"])
    ).fetchone()

# ═════════════════════════════════════════════════════════════════════════════
# TRACKER  (public endpoint — called by embedded script)
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/track", methods=["POST"])
def track():
    data  = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token or not get_site(token):
        return jsonify({"ok":False}),401

    ua = request.headers.get("User-Agent","")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if is_bot(ua):
        return jsonify({"ok":True,"filtered":"bot"}),200

    ev   = data.get("type","pageview")
    sess = hash_visitor(ip, ua)
    now  = datetime.now(timezone.utc)
    ref  = data.get("referrer","")
    dur  = int(data.get("duration",0))

    # Bounce detection
    bounce = 0
    if ev == "leave":
        pv = get_db().execute(
            "SELECT COUNT(*) n FROM events WHERE session_hash=? AND site_token=? AND event_type='pageview'",
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
        token, ev,
        data.get("path","/"), ref, ref_domain(ref),
        ip_to_country(ip), parse_device(ua), parse_browser(ua), parse_os(ua),
        sess, dur,
        int(data.get("scroll_pct",0)),
        data.get("element",""),
        data.get("cx"), data.get("cy"),
        now.hour, now.weekday(), bounce
    ))
    get_db().commit()
    return jsonify({"ok":True}),200

# ═════════════════════════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/auth/register", methods=["POST"])
def register():
    d  = request.get_json(silent=True) or {}
    em = d.get("email","").strip().lower()
    pw = d.get("password","")
    if not em or not pw: return jsonify({"error":"email and password required"}),400
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    api_key = secrets.token_urlsafe(32)
    try:
        get_db().execute("INSERT INTO users(email,password,api_key) VALUES(?,?,?)",(em,pw_hash,api_key))
        get_db().commit()
        return jsonify({"api_key":api_key,"email":em}),201
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email already registered"}),409

@app.route("/auth/login", methods=["POST"])
def login():
    d  = request.get_json(silent=True) or {}
    em = d.get("email","").strip().lower()
    pw = hashlib.sha256(d.get("password","").encode()).hexdigest()
    u  = get_db().execute("SELECT * FROM users WHERE email=? AND password=?",(em,pw)).fetchone()
    if not u: return jsonify({"error":"Invalid credentials"}),401
    return jsonify({"api_key":u["api_key"],"email":u["email"],"id":u["id"]}),200

# ═════════════════════════════════════════════════════════════════════════════
# SITES
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/sites", methods=["GET"])
@require_auth
def list_sites():
    rows = get_db().execute("SELECT * FROM sites WHERE user_id=? ORDER BY created DESC",(g.user["id"],)).fetchall()
    out = []
    for r in rows:
        pv   = get_db().execute("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now','-7 days')",(r["token"],)).fetchone()["n"]
        live = get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime('now','-5 minutes')",(r["token"],)).fetchone()["n"]
        out.append({**dict(r),"weekly_pageviews":pv,"live_now":live})
    return jsonify(out)

@app.route("/sites", methods=["POST"])
@require_auth
def create_site():
    d      = request.get_json(silent=True) or {}
    domain = d.get("domain","").strip().lower()
    name   = d.get("name", domain)
    if not domain: return jsonify({"error":"domain required"}),400
    token  = secrets.token_urlsafe(24)
    get_db().execute("INSERT INTO sites(user_id,domain,token,name) VALUES(?,?,?,?)",(g.user["id"],domain,token,name))
    get_db().commit()
    snippet = f'<script src="https://cdn.guestoom.com/tracker.js" data-token="{token}" async></script>'
    return jsonify({"domain":domain,"token":token,"name":name,"snippet":snippet}),201

@app.route("/sites/<token>", methods=["DELETE"])
@require_auth
def delete_site(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    get_db().execute("DELETE FROM sites WHERE token=?",(token,))
    get_db().execute("DELETE FROM events WHERE site_token=?",(token,))
    get_db().commit()
    return jsonify({"ok":True})

# ═════════════════════════════════════════════════════════════════════════════
# STATS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/stats/<token>", methods=["GET"])
@require_auth
def stats(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days  = int(request.args.get("days",7))
    since = f"-{days}"
    db    = get_db()
    def q(s,*p):  return db.execute(s,p).fetchall()
    def q1(s,*p): return db.execute(s,p).fetchone()

    tv  = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days')",token,since)["n"]
    tpv = q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days')",token,since)["n"]
    avg = q1("SELECT AVG(duration_seconds) a FROM events WHERE site_token=? AND event_type='leave' AND duration_seconds>0 AND ts>=datetime('now',? || ' days')",token,since)["a"] or 0
    live= q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND ts>=datetime('now','-5 minutes')",token)["n"]
    bnd = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND is_bounce=1 AND ts>=datetime('now',? || ' days')",token,since)["n"]
    br  = round((bnd/tv*100) if tv else 0,1)
    pv2 = q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') AND ts<datetime('now',? || ' days')",token,f"-{days*2}",since)["n"]
    dv  = round(((tv-pv2)/pv2*100) if pv2 else 0,1)

    # Duration buckets
    durs = q("SELECT duration_seconds FROM events WHERE site_token=? AND event_type='leave' AND duration_seconds>0 AND ts>=datetime('now',? || ' days')",token,since)
    bkts = {"0-10s":0,"10-30s":0,"30s-1m":0,"1-3m":0,"3-5m":0,"5m+":0}
    for r in durs:
        s=r["duration_seconds"]
        if s<10: bkts["0-10s"]+=1
        elif s<30: bkts["10-30s"]+=1
        elif s<60: bkts["30s-1m"]+=1
        elif s<180: bkts["1-3m"]+=1
        elif s<300: bkts["3-5m"]+=1
        else: bkts["5m+"]+=1

    # Scroll buckets
    scrls = q("SELECT scroll_pct FROM events WHERE site_token=? AND event_type='leave' AND scroll_pct>0 AND ts>=datetime('now',? || ' days')",token,since)
    sbkts = {"0-25%":0,"25-50%":0,"50-75%":0,"75-100%":0}
    for r in scrls:
        p=r["scroll_pct"]
        if p<=25: sbkts["0-25%"]+=1
        elif p<=50: sbkts["25-50%"]+=1
        elif p<=75: sbkts["50-75%"]+=1
        else: sbkts["75-100%"]+=1

    # Goals
    goals_raw = db.execute("SELECT * FROM goals WHERE site_token=?",(token,)).fetchall()
    goals_out = []
    for gr in goals_raw:
        if gr["goal_type"]=="path":
            conv=q1("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime('now',? || ' days')",token,gr["value"],since)["n"]
        else:
            conv=q1("SELECT COUNT(*) n FROM events WHERE site_token=? AND event_type='click' AND element=? AND ts>=datetime('now',? || ' days')",token,gr["value"],since)["n"]
        goals_out.append({"id":gr["id"],"name":gr["name"],"type":gr["goal_type"],"value":gr["value"],"conversions":conv,"rate":round((conv/tv*100) if tv else 0,2)})

    return jsonify({
        "summary":{"total_visitors":tv,"total_pageviews":tpv,"avg_session_seconds":round(avg),"live_now":live,"bounce_rate":br,"delta_visitors":dv},
        "by_day":          [dict(r) for r in q("SELECT DATE(ts) day,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY day ORDER BY day",token,since)],
        "countries":       [dict(r) for r in q("SELECT country,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY country ORDER BY visits DESC LIMIT 10",token,since)],
        "hourly":          [dict(r) for r in q("SELECT hour,COUNT(*) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY hour ORDER BY hour",token,since)],
        "top_pages":       [dict(r) for r in q("SELECT path,COUNT(*) views,COUNT(DISTINCT session_hash) uniq FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY path ORDER BY views DESC LIMIT 10",token,since)],
        "referrers":       [dict(r) for r in q("SELECT referrer_domain src,COUNT(DISTINCT session_hash) visits FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY referrer_domain ORDER BY visits DESC LIMIT 10",token,since)],
        "devices":         [dict(r) for r in q("SELECT device,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY device",token,since)],
        "browsers":        [dict(r) for r in q("SELECT browser,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY browser ORDER BY n DESC LIMIT 6",token,since)],
        "oses":            [dict(r) for r in q("SELECT os,COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND event_type='pageview' AND ts>=datetime('now',? || ' days') GROUP BY os ORDER BY n DESC LIMIT 6",token,since)],
        "session_buckets": [{"range":k,"count":v} for k,v in bkts.items()],
        "scroll_buckets":  [{"range":k,"count":v} for k,v in sbkts.items()],
        "top_elements":    [dict(r) for r in q("SELECT element,COUNT(*) clicks FROM events WHERE site_token=? AND event_type='click' AND element!='' AND ts>=datetime('now',? || ' days') GROUP BY element ORDER BY clicks DESC LIMIT 10",token,since)],
        "goals":           goals_out,
    })

# ═════════════════════════════════════════════════════════════════════════════
# HEATMAP
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/heatmap/<token>", methods=["GET"])
@require_auth
def heatmap(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    path = request.args.get("path","/")
    days = int(request.args.get("days",7))
    rows = get_db().execute("""
        SELECT ROUND(click_x_pct,1) x, ROUND(click_y_pct,1) y, COUNT(*) weight
        FROM events WHERE site_token=? AND event_type='click'
          AND path=? AND click_x_pct IS NOT NULL
          AND ts>=datetime('now',? || ' days')
        GROUP BY ROUND(click_x_pct,1), ROUND(click_y_pct,1)
    """,(token,path,f"-{days}")).fetchall()
    return jsonify({"path":path,"points":[dict(r) for r in rows]})

# ═════════════════════════════════════════════════════════════════════════════
# FUNNELS
# ═════════════════════════════════════════════════════════════════════════════
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
def funnel_stats(token, fid):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days = int(request.args.get("days",7))
    fn   = get_db().execute("SELECT * FROM funnels WHERE id=? AND site_token=?",(fid,token)).fetchone()
    if not fn: return jsonify({"error":"Not found"}),404
    steps = json.loads(fn["steps"])
    out, prev = [], None
    for i,path in enumerate(steps):
        n = get_db().execute("SELECT COUNT(DISTINCT session_hash) n FROM events WHERE site_token=? AND path=? AND ts>=datetime('now',? || ' days')",(token,path,f"-{days}")).fetchone()["n"]
        drop = round(((prev-n)/prev*100) if prev and prev>0 else 0,1)
        out.append({"step":i+1,"path":path,"sessions":n,"drop_pct":drop})
        prev = n
    return jsonify({"funnel":fn["name"],"steps":out})

# ═════════════════════════════════════════════════════════════════════════════
# GOALS
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/goals/<token>", methods=["POST"])
@require_auth
def create_goal(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    d = request.get_json(silent=True) or {}
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

# ═════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═════════════════════════════════════════════════════════════════════════════
@app.route("/export/<token>", methods=["GET"])
@require_auth
def export_csv(token):
    if not owns(token): return jsonify({"error":"Forbidden"}),403
    days = int(request.args.get("days",30))
    rows = get_db().execute("""
        SELECT event_type,path,country,device,browser,os,referrer_domain,
               duration_seconds,scroll_pct,element,hour,ts
        FROM events WHERE site_token=? AND ts>=datetime('now',? || ' days')
        ORDER BY ts DESC LIMIT 100000
    """,(token,f"-{days}")).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["type","path","country","device","browser","os","referrer","duration_s","scroll_pct","element","hour","timestamp"])
    for r in rows: w.writerow(list(r))
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    resp.headers["Content-Disposition"] = f"attachment; filename=guestoom-{token[:8]}.csv"
    return resp

@app.route("/health")
def health(): return jsonify({"status":"ok","product":"Guestoom","version":"2.0.0"})

if __name__ == "__main__":
    init_db()
    print("[Guestoom] Server → http://localhost:5000")
    app.run(debug=True,host="0.0.0.0",port=5000)
