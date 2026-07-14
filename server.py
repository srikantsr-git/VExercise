"""
VExercise v3 - Full-stack fitness app backend
  * SQLite: exercises + favorites + workout_plans + users + profiles + selfies
  * Session-based auth (SHA-256 salted passwords)
  * Roles: user / admin   |   Default: admin / admin123
"""

import json, os, sqlite3, uuid, hashlib, secrets, functools
from datetime import datetime, timezone
from flask import (Flask, g, jsonify, request,
                   send_from_directory, send_file, session)

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, "data", "exercises.db")
JSON_PATH = os.path.join(BASE_DIR, "data", "exercises.json")
SK_PATH   = os.path.join(BASE_DIR, "data", ".sk")

os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
if os.path.exists(SK_PATH):
    with open(SK_PATH) as f:
        _SK = f.read().strip()
else:
    _SK = secrets.token_hex(32)
    with open(SK_PATH, "w") as f:
        f.write(_SK)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = _SK
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"]      = origin or "*"
    response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return "", 204

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def make_salt():
    return secrets.token_hex(16)

def hash_pw(pw, salt):
    return hashlib.sha256((salt + pw).encode()).hexdigest()

def verify_pw(pw, salt, stored):
    return hash_pw(pw, salt) == stored

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS exercises (
            id TEXT PRIMARY KEY, name TEXT NOT NULL,
            category TEXT, body_part TEXT, equipment TEXT, target TEXT,
            muscle_group TEXT, secondary_muscles TEXT, media_id TEXT,
            image TEXT, gif_url TEXT, attribution TEXT, created_at TEXT,
            instr_en TEXT, instr_es TEXT, instr_it TEXT,
            instr_tr TEXT, instr_ru TEXT, instr_zh TEXT,
            instr_hi TEXT, instr_pl TEXT, instr_ko TEXT,
            steps_en TEXT, steps_es TEXT, steps_it TEXT,
            steps_tr TEXT, steps_ru TEXT, steps_zh TEXT,
            steps_hi TEXT, steps_pl TEXT, steps_ko TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_category  ON exercises(category);
        CREATE INDEX IF NOT EXISTS idx_equipment ON exercises(equipment);
        CREATE INDEX IF NOT EXISTS idx_target    ON exercises(target);
        CREATE INDEX IF NOT EXISTS idx_body_part ON exercises(body_part);
        CREATE INDEX IF NOT EXISTS idx_name      ON exercises(name COLLATE NOCASE);
        CREATE TABLE IF NOT EXISTS favorites (
            id TEXT PRIMARY KEY, exercise_id TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(exercise_id)
        );
        CREATE INDEX IF NOT EXISTS idx_fav_exercise ON favorites(exercise_id);
        CREATE TABLE IF NOT EXISTS workout_plans (
            id TEXT PRIMARY KEY, name TEXT NOT NULL,
            exercises TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT,
            phone         TEXT,
            address       TEXT,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_user_username ON users(username);
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id      TEXT PRIMARY KEY,
            display_name TEXT,
            bio          TEXT,
            age          INTEGER,
            weight_kg    REAL,
            height_cm    REAL,
            avatar_data  TEXT,
            updated_at   TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS exercise_selfies (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            date       TEXT NOT NULL,
            image_data TEXT NOT NULL,
            caption    TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_selfie_user_date ON exercise_selfies(user_id, date);
        CREATE TABLE IF NOT EXISTS exercise_videos (
            exercise_id TEXT PRIMARY KEY,
            video_url   TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
    """)
    con.commit()

    count = con.execute("SELECT COUNT(*) FROM exercises").fetchone()[0]
    if count == 0:
        print(f"[DB] Importing exercises ...")
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            exercises = json.load(f)
        for ex in exercises:
            instr = ex.get("instructions", {}) or {}
            steps = ex.get("instruction_steps", {}) or {}
            sm    = ex.get("secondary_muscles", []) or []
            cur.execute("""
                INSERT OR IGNORE INTO exercises VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ex.get("id"), ex.get("name"), ex.get("category"),
                ex.get("body_part"), ex.get("equipment"), ex.get("target"),
                ex.get("muscle_group"), json.dumps(sm), ex.get("media_id"),
                ex.get("image"), ex.get("gif_url"), ex.get("attribution"), ex.get("created_at"),
                instr.get("en"), instr.get("es"), instr.get("it"),
                instr.get("tr"), instr.get("ru"), instr.get("zh"),
                instr.get("hi"), instr.get("pl"), instr.get("ko"),
                json.dumps(steps.get("en",[])), json.dumps(steps.get("es",[])),
                json.dumps(steps.get("it",[])), json.dumps(steps.get("tr",[])),
                json.dumps(steps.get("ru",[])), json.dumps(steps.get("zh",[])),
                json.dumps(steps.get("hi",[])), json.dumps(steps.get("pl",[])),
                json.dumps(steps.get("ko",[])),
            ))
        con.commit()
        print(f"[DB] [OK] {len(exercises)} exercises imported.")
    else:
        print(f"[DB] [OK] Database ready -- {count} exercises.")

    ucount = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if ucount == 0:
        salt  = make_salt()
        phash = hash_pw("admin123", salt)
        uid   = str(uuid.uuid4())
        ts    = now_iso()
        con.execute(
            "INSERT INTO users (id,username,email,password_hash,salt,role,is_active,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (uid, "admin", "admin@vexercise.local", phash, salt, "admin", 1, ts))
        con.execute(
            "INSERT INTO user_profiles (user_id,display_name,updated_at) VALUES (?,?,?)",
            (uid, "Administrator", ts))
        con.commit()
        print("[DB] [OK] Default admin: admin / admin123")
    con.close()

def row_to_dict(row):
    d = dict(row)
    for key in ("secondary_muscles","steps_en","steps_es","steps_it",
                "steps_tr","steps_ru","steps_zh","steps_hi","steps_pl","steps_ko"):
        if d.get(key):
            try: d[key] = json.loads(d[key])
            except: pass
    d["instructions"]     = {l: d.pop(f"instr_{l}", None) for l in ("en","es","it","tr","ru","zh","hi","pl","ko")}
    d["instruction_steps"]= {l: d.pop(f"steps_{l}", [])   for l in ("en","es","it","tr","ru","zh","hi","pl","ko")}
    return d

def user_safe(row):
    d = dict(row)
    d.pop("password_hash", None); d.pop("salt", None)
    return d

# ---- AUTH ----
@app.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    username = data.get("username","").strip()
    email    = data.get("email","").strip() or None
    phone    = data.get("phone","").strip() or None
    address  = data.get("address","").strip() or None
    password = data.get("password","")
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    if len(username) < 3:
        return jsonify({"error":"Username must be >= 3 chars"}), 400
    if len(password) < 6:
        return jsonify({"error":"Password must be >= 6 chars"}), 400
    db = get_db(); salt = make_salt(); phash = hash_pw(password, salt)
    uid = str(uuid.uuid4()); ts = now_iso()
    try:
        db.execute("INSERT INTO users (id,username,email,phone,address,password_hash,salt,role,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (uid, username, email, phone, address, phash, salt, "user", 1, ts))
        db.execute("INSERT INTO user_profiles (user_id,display_name,updated_at) VALUES (?,?,?)",(uid, username, ts))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username already taken"}), 409
    session["user_id"] = uid; session["username"] = username; session["role"] = "user"
    return jsonify({"id":uid,"username":username,"role":"user"}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username","").strip()
    password = data.get("password","")
    if not username or not password:
        return jsonify({"error":"username and password required"}), 400
    db  = get_db()
    row = db.execute("SELECT * FROM users WHERE username=? AND is_active=1",(username,)).fetchone()
    if not row or not verify_pw(password, row["salt"], row["password_hash"]):
        return jsonify({"error":"Invalid username or password"}), 401
    session["user_id"] = row["id"]; session["username"] = row["username"]; session["role"] = row["role"]
    return jsonify({"id":row["id"],"username":row["username"],"role":row["role"]})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear(); return jsonify({"ok":True})

@app.route("/api/auth/me", methods=["GET"])
def me():
    if "user_id" not in session:
        return jsonify({"error":"Not authenticated"}), 401
    db  = get_db()
    row = db.execute("SELECT u.*,p.display_name,p.avatar_data FROM users u LEFT JOIN user_profiles p ON u.id=p.user_id WHERE u.id=?",
                     (session["user_id"],)).fetchone()
    if not row:
        session.clear(); return jsonify({"error":"User not found"}), 401
    return jsonify(user_safe(row))

# ---- PROFILE ----
@app.route("/api/profile", methods=["GET"])
@login_required
def get_profile():
    db = get_db(); uid = session["user_id"]
    u  = db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    p  = db.execute("SELECT * FROM user_profiles WHERE user_id=?",(uid,)).fetchone()
    if not u: return jsonify({"error":"User not found"}), 404
    result = user_safe(u); result["profile"] = dict(p) if p else {}
    return jsonify(result)

@app.route("/api/profile", methods=["PUT","POST"])
@login_required
def update_profile():
    data = request.get_json(silent=True) or {}
    db = get_db(); uid = session["user_id"]; ts = now_iso()
    for field in ("email","phone","address"):
        if field in data:
            db.execute(f"UPDATE users SET {field}=? WHERE id=?",(data[field] or None, uid))
    pf = ("display_name","bio","age","weight_kg","height_cm","avatar_data")
    exists = db.execute("SELECT user_id FROM user_profiles WHERE user_id=?",(uid,)).fetchone()
    if exists:
        for field in pf:
            if field in data:
                db.execute(f"UPDATE user_profiles SET {field}=?,updated_at=? WHERE user_id=?",(data[field],ts,uid))
    else:
        db.execute("INSERT INTO user_profiles (user_id,display_name,bio,age,weight_kg,height_cm,avatar_data,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                   (uid,data.get("display_name"),data.get("bio"),data.get("age"),data.get("weight_kg"),data.get("height_cm"),data.get("avatar_data"),ts))
    db.commit(); return jsonify({"ok":True})

# ---- SELFIES ----
@app.route("/api/selfies", methods=["GET"])
@login_required
def get_selfies():
    db = get_db(); uid = session["user_id"]
    date = request.args.get("date","").strip()
    year = request.args.get("year","").strip()
    month = request.args.get("month","").strip()
    full = request.args.get("full","").strip() in ("1", "true")
    cols = "id,date,image_data,caption,created_at" if full else "id,date,caption,created_at"
    if date:
        rows = db.execute(f"SELECT {cols} FROM exercise_selfies WHERE user_id=? AND date=? ORDER BY created_at",(uid,date)).fetchall()
    elif year and month:
        rows = db.execute(f"SELECT {cols} FROM exercise_selfies WHERE user_id=? AND date LIKE ? ORDER BY date,created_at",(uid,f"{year}-{month.zfill(2)}%")).fetchall()
    else:
        rows = db.execute(f"SELECT {cols} FROM exercise_selfies WHERE user_id=? ORDER BY date DESC LIMIT 50",(uid,)).fetchall()
    return jsonify({"data":[dict(r) for r in rows]})

@app.route("/api/selfies/full/<selfie_id>", methods=["GET"])
@login_required
def get_selfie_full(selfie_id):
    db = get_db(); uid = session["user_id"]
    row = db.execute("SELECT * FROM exercise_selfies WHERE id=? AND user_id=?",(selfie_id,uid)).fetchone()
    if not row: return jsonify({"error":"Not found"}), 404
    return jsonify(dict(row))

@app.route("/api/selfies", methods=["POST"])
@login_required
def add_selfie():
    data = request.get_json(silent=True) or {}
    uid = session["user_id"]
    date = data.get("date","").strip(); img = data.get("image_data","").strip()
    caption = data.get("caption","").strip() or None
    if not date or not img: return jsonify({"error":"date and image_data required"}), 400
    try: datetime.strptime(date,"%Y-%m-%d")
    except ValueError: return jsonify({"error":"date must be YYYY-MM-DD"}), 400
    db = get_db(); sid = str(uuid.uuid4()); ts = now_iso()
    db.execute("INSERT INTO exercise_selfies (id,user_id,date,image_data,caption,created_at) VALUES (?,?,?,?,?,?)",
               (sid,uid,date,img,caption,ts))
    db.commit()
    return jsonify({"id":sid,"date":date,"caption":caption,"created_at":ts}), 201

@app.route("/api/selfies/<selfie_id>", methods=["DELETE"])
@login_required
def delete_selfie(selfie_id):
    db = get_db(); uid = session["user_id"]
    db.execute("DELETE FROM exercise_selfies WHERE id=? AND user_id=?",(selfie_id,uid))
    db.commit(); return jsonify({"deleted":selfie_id})

# ---- ADMIN ----
@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    db = get_db()
    return jsonify({"users":db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                    "admins":db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0],
                    "selfies":db.execute("SELECT COUNT(*) FROM exercise_selfies").fetchone()[0],
                    "workouts":db.execute("SELECT COUNT(*) FROM workout_plans").fetchone()[0],
                    "favorites":db.execute("SELECT COUNT(*) FROM favorites").fetchone()[0],
                    "exercises":db.execute("SELECT COUNT(*) FROM exercises").fetchone()[0]})

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_get_users():
    db   = get_db()
    rows = db.execute("SELECT u.id,u.username,u.email,u.phone,u.address,u.role,u.is_active,u.created_at,p.display_name,p.avatar_data FROM users u LEFT JOIN user_profiles p ON u.id=p.user_id ORDER BY u.created_at DESC").fetchall()
    return jsonify({"data":[dict(r) for r in rows]})

@app.route("/api/admin/users/<uid>", methods=["PUT"])
@admin_required
def admin_update_user(uid):
    data = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not row: return jsonify({"error":"User not found"}), 404
    if "role" in data and row["role"]=="admin" and data["role"]!="admin":
        if db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]<=1:
            return jsonify({"error":"Cannot demote the only admin"}), 400
    for field in ("role","is_active","email","phone","address"):
        if field in data: db.execute(f"UPDATE users SET {field}=? WHERE id=?",(data[field],uid))
    if "display_name" in data:
        db.execute("UPDATE user_profiles SET display_name=? WHERE user_id=?",(data["display_name"],uid))
    db.commit(); return jsonify({"ok":True})

@app.route("/api/admin/users/<uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    if uid == session["user_id"]: return jsonify({"error":"Cannot delete your own account"}), 400
    db = get_db()
    row = db.execute("SELECT role FROM users WHERE id=?",(uid,)).fetchone()
    if not row: return jsonify({"error":"User not found"}), 404
    if row["role"]=="admin" and db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]<=1:
        return jsonify({"error":"Cannot delete the only admin"}), 400
    db.execute("DELETE FROM exercise_selfies WHERE user_id=?",(uid,))
    db.execute("DELETE FROM user_profiles WHERE user_id=?",(uid,))
    db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit(); return jsonify({"deleted":uid})

# ---- EXERCISE VIDEOS ----
@app.route("/api/exercises/<exercise_id>/video", methods=["GET"])
def get_exercise_video(exercise_id):
    db = get_db()
    row = db.execute("SELECT * FROM exercise_videos WHERE exercise_id=?", (exercise_id,)).fetchone()
    if not row:
        return jsonify({"video_url": None})
    return jsonify({"exercise_id": row["exercise_id"], "video_url": row["video_url"], "updated_at": row["updated_at"]})

@app.route("/api/admin/exercises/<exercise_id>/video", methods=["PUT", "POST"])
@admin_required
def set_exercise_video(exercise_id):
    data = request.get_json(silent=True) or {}
    video_url = data.get("video_url", "").strip()
    if not video_url:
        return jsonify({"error": "video_url is required"}), 400
    db = get_db()
    ex = db.execute("SELECT id FROM exercises WHERE id=?", (exercise_id,)).fetchone()
    if not ex:
        return jsonify({"error": "Exercise not found"}), 404
    ts = now_iso()
    db.execute(
        "INSERT INTO exercise_videos (exercise_id, video_url, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(exercise_id) DO UPDATE SET video_url=excluded.video_url, updated_at=excluded.updated_at",
        (exercise_id, video_url, ts))
    db.commit()
    return jsonify({"exercise_id": exercise_id, "video_url": video_url, "updated_at": ts})

@app.route("/api/admin/exercises/<exercise_id>/video", methods=["DELETE"])
@admin_required
def delete_exercise_video(exercise_id):
    db = get_db()
    db.execute("DELETE FROM exercise_videos WHERE exercise_id=?", (exercise_id,))
    db.commit()
    return jsonify({"deleted": exercise_id})

@app.route("/api/admin/exercises/videos", methods=["GET"])
@admin_required
def list_exercise_videos():
    db = get_db()
    rows = db.execute(
        "SELECT ev.exercise_id, e.name, ev.video_url, ev.updated_at "
        "FROM exercise_videos ev JOIN exercises e ON e.id=ev.exercise_id "
        "ORDER BY ev.updated_at DESC"
    ).fetchall()
    return jsonify({"data": [dict(r) for r in rows]})

# ---- EXERCISES ----
@app.route("/api/exercises", methods=["GET"])
def get_exercises():
    db = get_db()
    try:
        lp = request.args.get("limit","20")
        limit = None if lp.lower() in ("all","0") else min(2000, max(1,int(lp)))
    except: limit = 20
    try: page = max(1,int(request.args.get("page",1))); offset = (page-1)*(limit or 0)
    except: page,offset = 1,0
    search = request.args.get("search","").strip(); category = request.args.get("category","").strip()
    equipment = request.args.get("equipment","").strip(); target = request.args.get("target","").strip()
    body_part = request.args.get("body_part","").strip(); sort = request.args.get("sort","").strip()
    where,params = [],[]
    if search:    where.append("(name LIKE ? OR instr_en LIKE ?)"); params+=[f"%{search}%"]*2
    if category:  where.append("category=?"); params.append(category)
    if equipment: where.append("equipment=?"); params.append(equipment)
    if target:    where.append("target=?"); params.append(target)
    if body_part: where.append("body_part=?"); params.append(body_part)
    wsql = ("WHERE "+" AND ".join(where)) if where else ""
    osql = "ORDER BY "+{"az":"name ASC","za":"name DESC","cat":"category,name","equip":"equipment,name"}.get(sort,"id ASC")
    total = db.execute(f"SELECT COUNT(*) FROM exercises {wsql}",params).fetchone()[0]
    if limit is None:
        rows = db.execute(f"SELECT * FROM exercises {wsql} {osql}",params).fetchall(); pages=1
    else:
        rows = db.execute(f"SELECT * FROM exercises {wsql} {osql} LIMIT ? OFFSET ?",params+[limit,offset]).fetchall()
        pages = (total+limit-1)//limit
    return jsonify({"total":total,"page":page,"limit":limit or total,"pages":pages,"data":[row_to_dict(r) for r in rows]})

@app.route("/api/exercises/<exercise_id>", methods=["GET"])
def get_exercise(exercise_id):
    db = get_db()
    row = db.execute("SELECT * FROM exercises WHERE id=?",(exercise_id,)).fetchone()
    if row is None: return jsonify({"error":"Exercise not found"}), 404
    return jsonify(row_to_dict(row))

@app.route("/api/filters", methods=["GET"])
def get_filters():
    db = get_db()
    def d(col): return [r[0] for r in db.execute(f"SELECT DISTINCT {col} FROM exercises WHERE {col} IS NOT NULL ORDER BY {col}").fetchall()]
    return jsonify({"categories":d("category"),"equipments":d("equipment"),"targets":d("target"),"body_parts":d("body_part")})

@app.route("/api/stats", methods=["GET"])
def get_stats():
    db = get_db()
    return jsonify({"total_exercises":db.execute("SELECT COUNT(*) FROM exercises").fetchone()[0],
                    "by_category":[{"name":r[0],"count":r[1]} for r in db.execute("SELECT category,COUNT(*) c FROM exercises GROUP BY category ORDER BY c DESC").fetchall()],
                    "by_equipment":[{"name":r[0],"count":r[1]} for r in db.execute("SELECT equipment,COUNT(*) c FROM exercises GROUP BY equipment ORDER BY c DESC").fetchall()],
                    "by_target":[{"name":r[0],"count":r[1]} for r in db.execute("SELECT target,COUNT(*) c FROM exercises GROUP BY target ORDER BY c DESC").fetchall()],
                    "by_body_part":[{"name":r[0],"count":r[1]} for r in db.execute("SELECT body_part,COUNT(*) c FROM exercises GROUP BY body_part ORDER BY c DESC").fetchall()]})

@app.route("/api/health", methods=["GET"])
def health():
    db = get_db()
    return jsonify({"status":"ok","exercises":db.execute("SELECT COUNT(*) FROM exercises").fetchone()[0],
                    "users":db.execute("SELECT COUNT(*) FROM users").fetchone()[0],"version":"3.0"})

# ---- FAVORITES ----
@app.route("/api/favorites", methods=["GET"])
def get_favorites():
    db = get_db(); rows = db.execute("SELECT * FROM favorites ORDER BY created_at DESC").fetchall()
    return jsonify({"data":[dict(r) for r in rows]})

@app.route("/api/favorites", methods=["POST"])
def add_favorite():
    data = request.get_json(silent=True) or {}; eid = data.get("exercise_id","").strip()
    if not eid: return jsonify({"error":"exercise_id required"}), 400
    db = get_db()
    if not db.execute("SELECT id FROM exercises WHERE id=?",(eid,)).fetchone():
        return jsonify({"error":"Exercise not found"}), 404
    fid = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO favorites (id,exercise_id,created_at) VALUES (?,?,?)",(fid,eid,now_iso()))
        db.commit(); return jsonify({"id":fid,"exercise_id":eid}), 201
    except sqlite3.IntegrityError: return jsonify({"message":"Already a favorite"}), 200

@app.route("/api/favorites/sync", methods=["POST"])
def sync_favorites():
    data = request.get_json(silent=True) or {}; ids = data.get("exercise_ids",[])
    db = get_db(); db.execute("DELETE FROM favorites")
    for eid in ids:
        try: db.execute("INSERT OR IGNORE INTO favorites (id,exercise_id,created_at) VALUES (?,?,?)",(str(uuid.uuid4()),eid,now_iso()))
        except: pass
    db.commit(); return jsonify({"synced":len(ids)})

@app.route("/api/favorites/<exercise_id>", methods=["DELETE"])
def remove_favorite(exercise_id):
    db = get_db(); db.execute("DELETE FROM favorites WHERE exercise_id=?",(exercise_id,))
    db.commit(); return jsonify({"deleted":exercise_id})

# ---- WORKOUTS ----
@app.route("/api/workouts", methods=["GET"])
def get_workouts():
    db = get_db(); rows = db.execute("SELECT * FROM workout_plans ORDER BY updated_at DESC").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try: d["exercises"] = json.loads(d["exercises"])
        except: d["exercises"] = []
        result.append(d)
    return jsonify({"data":result})

@app.route("/api/workouts", methods=["POST"])
def create_workout():
    data = request.get_json(silent=True) or {}; name = data.get("name","").strip()
    if not name: return jsonify({"error":"name required"}), 400
    wid = data.get("id") or str(uuid.uuid4()); exs = data.get("exercises",[]); ts = now_iso()
    db = get_db()
    db.execute("INSERT OR REPLACE INTO workout_plans (id,name,exercises,created_at,updated_at) VALUES (?,?,?,?,?)",(wid,name,json.dumps(exs),ts,ts))
    db.commit(); return jsonify({"id":wid,"name":name,"exercises":exs,"created_at":ts,"updated_at":ts}), 201

@app.route("/api/workouts/<wid>", methods=["GET"])
def get_workout(wid):
    db = get_db(); row = db.execute("SELECT * FROM workout_plans WHERE id=?",(wid,)).fetchone()
    if row is None: return jsonify({"error":"Workout not found"}), 404
    d = dict(row)
    try: d["exercises"] = json.loads(d["exercises"])
    except: d["exercises"] = []
    return jsonify(d)

@app.route("/api/workouts/<wid>", methods=["PUT"])
def update_workout(wid):
    data = request.get_json(silent=True) or {}; db = get_db()
    row = db.execute("SELECT * FROM workout_plans WHERE id=?",(wid,)).fetchone(); ts = now_iso()
    if row is None:
        name = data.get("name","Unnamed"); exs = data.get("exercises",[])
        db.execute("INSERT INTO workout_plans (id,name,exercises,created_at,updated_at) VALUES (?,?,?,?,?)",(wid,name,json.dumps(exs),ts,ts))
        db.commit(); return jsonify({"id":wid,"name":name,"exercises":exs}), 201
    name = data.get("name",row["name"]); exs = data.get("exercises",json.loads(row["exercises"] or "[]"))
    db.execute("UPDATE workout_plans SET name=?,exercises=?,updated_at=? WHERE id=?",(name,json.dumps(exs),ts,wid))
    db.commit(); return jsonify({"id":wid,"name":name,"exercises":exs,"updated_at":ts})

@app.route("/api/workouts/<wid>", methods=["DELETE"])
def delete_workout(wid):
    db = get_db(); db.execute("DELETE FROM workout_plans WHERE id=?",(wid,))
    db.commit(); return jsonify({"deleted":wid})

# ---- STATIC ----
@app.route("/")
def index(): return send_file(os.path.join(BASE_DIR,"index.html"))

@app.route("/login")
def login_page(): return send_file(os.path.join(BASE_DIR,"login.html"))

@app.route("/admin")
def admin_page(): return send_file(os.path.join(BASE_DIR,"admin.html"))

@app.route("/setup")
@app.route("/setup.html")
def setup(): return send_file(os.path.join(BASE_DIR,"setup.html"))

@app.route("/images/<path:filename>")
def serve_image(filename): return send_from_directory(os.path.join(BASE_DIR,"images"),filename)

@app.route("/videos/<path:filename>")
def serve_video(filename): return send_from_directory(os.path.join(BASE_DIR,"videos"),filename)

@app.route("/data/<path:filename>")
def serve_data(filename): return send_from_directory(os.path.join(BASE_DIR,"data"),filename)

if __name__ == "__main__":
    init_db()
    print("\n"+"="*54)
    print("  VExercise v3 -- http://localhost:8765")
    print("="*54)
    print("  App:   http://localhost:8765/")
    print("  Login: http://localhost:8765/login")
    print("  Admin: http://localhost:8765/admin")
    print("  Creds: admin / admin123")
    print("="*54+"\n")
    app.run(host="0.0.0.0", port=8765, debug=False)
