# sbos_server_shadow.py
import os, time, json, yaml, sqlite3, threading, subprocess, signal
from typing import Dict, List, Optional, Tuple
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from brickschema.graph import Graph
from jinja2 import Template

MODEL_FILE = "model.ttl"
POLICY_FILE = "policy.yaml"
PROFILES_FILE = "permission_profiles.yaml"
USERS_FILE = "users.yaml"
DB_FILE = "sbos.db"

app = FastAPI(title="Playground-like SBOS + Shadow Guards")

# ---------------- Persistence ----------------
def db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

DB = db()
DB.execute("""CREATE TABLE IF NOT EXISTS txlog(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, actor TEXT, app_id TEXT, user_id TEXT, action TEXT,
  point_iri TEXT, point_label TEXT, value REAL, decision TEXT, reason TEXT
);""")
DB.execute("""CREATE TABLE IF NOT EXISTS constraints(
  key TEXT PRIMARY KEY, value TEXT
);""")
DB.execute("""CREATE TABLE IF NOT EXISTS validators(
  resource_class TEXT, position INTEGER, vtype TEXT
);""")
DB.execute("""CREATE TABLE IF NOT EXISTS shadow_validators(
  resource_class TEXT, position INTEGER, vtype TEXT
);""")
DB.execute("""CREATE TABLE IF NOT EXISTS timeseries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, point_label TEXT, value REAL
);""")
DB.execute("""CREATE TABLE IF NOT EXISTS shadowlog(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, app_id TEXT, user_id TEXT, point_iri TEXT, point_label TEXT,
  value REAL, cls TEXT, vtype TEXT, reason TEXT
);""")
DB.commit()

# ---------------- Global state, caches, update lock ----------------
G = Graph()
PROFILES = {}
POLICY = {}
USERS = {}
IRI2LABEL: Dict[str,str] = {}
LABEL2IRI: Dict[str,str] = {}
UPDATE_LOCK = threading.RLock()

def load_all():
    global G, PROFILES, POLICY, USERS, IRI2LABEL, LABEL2IRI
    with UPDATE_LOCK:
        G = Graph()
        G.load_file(MODEL_FILE)
        PROFILES = yaml.safe_load(open(PROFILES_FILE))
        POLICY = yaml.safe_load(open(POLICY_FILE))
        USERS = yaml.safe_load(open(USERS_FILE))
        IRI2LABEL.clear(); LABEL2IRI.clear()
        rows = G.query("""
          PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
          SELECT ?pt ?lbl WHERE { ?pt rdfs:label ?lbl . }
        """)
        for r in rows:
            IRI2LABEL[str(r["pt"])] = str(r["lbl"])
            LABEL2IRI[str(r["lbl"])] = str(r["pt"])
        with DB:
            for k,v in POLICY.get("constraints", {}).items():
                DB.execute("INSERT OR REPLACE INTO constraints(key,value) VALUES(?,?)", (k, json.dumps(v)))
            DB.execute("DELETE FROM validators")
            for cls, arr in POLICY.get("validators", {}).get("defaults", {}).items():
                for pos, spec in enumerate(arr):
                    DB.execute("INSERT INTO validators(resource_class,position,vtype) VALUES(?,?,?)", (cls, pos, spec["type"]))
            DB.execute("DELETE FROM shadow_validators")
            for cls, arr in POLICY.get("shadow_validators", {}).get("defaults", {}).items():
                for pos, spec in enumerate(arr):
                    DB.execute("INSERT INTO shadow_validators(resource_class,position,vtype) VALUES(?,?,?)", (cls, pos, spec["type"]))

load_all()

# ---------------- Brick helpers ----------------
def query_iris(sparql: str) -> List[str]:
    rows = G.query(sparql)
    return [str(r["pt"]) for r in rows]

def class_of_iri(iri: str) -> Optional[str]:
    rows = G.query(f"SELECT ?cls WHERE {{ <{iri}> a ?cls . }}")
    for r in rows:
        return str(r["cls"])
    return None

def require_typed_label(label: str, brick_type_qname: str):
    rows = G.query(f"""
      PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
      PREFIX brick: <https://brickschema.org/schema/Brick#>
      SELECT ?x WHERE {{ ?x a {brick_type_qname} ; rdfs:label "{label}" . }}
    """)
    if not any(True for _ in rows):
        raise HTTPException(400, f"Typed argument check failed: label '{label}' is not a {brick_type_qname}")

# ---------------- Permission Manager ----------------
from dataclasses import dataclass
@dataclass
class Manifest:
    app_id: str
    profile: str
    args: Dict[str,str]
    delegation: str
    write_rate_limit_per_min: int
    permissions: Dict[str,bool]
    user: str

def render_profile(profile: str, args: Dict[str,str]) -> str:
    pf = PROFILES["profiles"][profile]
    for arg_name, meta in pf.get("args", {}).items():
        if arg_name in args and "type" in meta:
            require_typed_label(args[arg_name], meta["type"])
    tpl = Template(pf["sparql"])
    return tpl.render(**args)

def user_caps(user: str, op: str) -> List[str]:
    u = USERS["users"].get(user, {})
    key = f"sparql_{op}"
    if key not in u:
        return []
    return query_iris(u[key])

def compute_caps(man: Manifest) -> Dict[str,List[str]]:
    app_read = query_iris(render_profile(man.profile, man.args))
    app_write = app_read[:] if man.permissions.get("write", False) else []
    if man.delegation == "augmentation":
        return {"read": app_read, "write": app_write}
    uread = user_caps(man.user, "read")
    uwrite = user_caps(man.user, "write")
    return {
        "read": [i for i in app_read if i in uread],
        "write": [i for i in app_write if i in uwrite],
    }

APPS: Dict[str, Dict] = {}    # app_instance_id -> {manifest,pid,key,caps,user,rate}
APP_KEYS: Dict[str, str] = {}  # api_key -> app_instance_id

# ---------------- Resource Proxy + logs ----------------
STATE: Dict[str,float] = {
    "F1_ZoneA_Cool_SP": 22.0,
    "F1_ZoneA_Heat_SP": 21.0,
    "F2_ZoneB_Cool_SP": 22.0,
    "F2_ZoneB_Heat_SP": 21.0,
}

def log_tx(actor, app_id, user_id, action, iri, label, value, decision, reason):
    with DB:
        DB.execute("INSERT INTO txlog(ts,actor,app_id,user_id,action,point_iri,point_label,value,decision,reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (time.time(), actor, app_id, user_id, action, iri, label, value, decision, reason))

def log_timeseries(label: str, value: float):
    with DB:
        DB.execute("INSERT INTO timeseries(ts,point_label,value) VALUES(?,?,?)", (time.time(), label, value))

def log_shadow(app_id, user_id, iri, label, value, cls, vtype, reason):
    with DB:
        DB.execute("INSERT INTO shadowlog(ts,app_id,user_id,point_iri,point_label,value,cls,vtype,reason) VALUES(?,?,?,?,?,?,?,?,?)",
                   (time.time(), app_id, user_id, iri, label, value, cls, vtype, reason))

def proxy_read(label: str) -> Optional[float]:
    return STATE.get(label, None)

def proxy_write(label: str, value: float):
    STATE[label] = value
    log_timeseries(label, value)

# ---------------- Validators (enforced + shadow) ----------------
def get_constraints() -> Dict[str, any]:
    cur = DB.execute("SELECT key,value FROM constraints")
    return {k: json.loads(v) for (k,v) in cur.fetchall()}

def get_validators_for_class(cls: str) -> List[str]:
    local = cls.split("#")[-1] if "#" in cls else cls
    cur = DB.execute("SELECT vtype FROM validators WHERE resource_class=? ORDER BY position ASC", (local,))
    return [r[0] for r in cur.fetchall()]

def get_shadow_validators_for_class(cls: str) -> List[str]:
    local = cls.split("#")[-1] if "#" in cls else cls
    cur = DB.execute("SELECT vtype FROM shadow_validators WHERE resource_class=? ORDER BY position ASC", (local,))
    return [r[0] for r in cur.fetchall()]

def v_range(cls: str, label: str, value: float, prev: Optional[float]) -> Tuple[bool,str]:
    local = cls.split("#")[-1] if "#" in cls else cls
    g = POLICY["guards"].get(local, None)
    if not g:
        return True, "no-range"
    if value < g["min"] or value > g["max"]:
        return False, f"range {g['min']}–{g['max']}"
    return True, "ok"

def v_rate(cls: str, label: str, value: float, prev: Optional[float]) -> Tuple[bool,str]:
    local = cls.split("#")[-1] if "#" in cls else cls
    g = POLICY["guards"].get(local, None)
    if not g or prev is None:
        return True, "no-rate"
    if abs(value - prev) > g["max_step"]:
        return False, f"step>{g['max_step']}"
    return True, "ok"

def v_energy_budget(cls: str, label: str, value: float, prev: Optional[float]) -> Tuple[bool,str]:
    c = get_constraints()
    watts = c.get("energy_budget_watts", 5000)
    per_deg = c.get("energy_per_degree_watts", 150)
    if "Cool_SP" in label and value < c.get("min_cool_setpoint", 20.0):
        need = int((20.0 - value) * per_deg)
        if need > watts:
            return False, "energy_budget"
    return True, "ok"

# comfort band (21–24 C) to evaluate stricter policy without enforcement
def v_comfort_band(cls: str, label: str, value: float, prev: Optional[float]) -> Tuple[bool,str]:
    c = get_constraints()
    lo = c.get("comfort_min", 21.0)
    hi = c.get("comfort_max", 24.0)
    if value < lo or value > hi:
        return False, f"comfort_band {lo}–{hi}"
    return True, "ok"

VALIDATOR_FUNS = {
    "range": v_range,
    "rate": v_rate,
    "energy_budget": v_energy_budget,
    "comfort_band": v_comfort_band,  
}

# ---------------- Live monitor ----------------
RISK = {"cooling_low_excess": False}
MON_RUNNING = True

def monitor_loop():
    while True:
        if not MON_RUNNING:
            time.sleep(0.5); continue
        cfg = POLICY.get("monitor", {})
        window = cfg.get("window_seconds", 12)
        threshold = cfg.get("threshold_count", 5)
        cmin = cfg.get("cooling_min", 20.0)
        reset = cfg.get("cooling_reset", 22.0)
        cnt = 0; start = time.time()
        while time.time() - start < window:
            for k,v in STATE.items():
                if "Cool_SP" in k and v < cmin:
                    cnt += 1
            time.sleep(1)
        if cnt >= threshold:
            RISK["cooling_low_excess"] = True
            for act in cfg.get("actions", []):
                if act["type"] == "reset_points":
                    for k in list(STATE.keys()):
                        if act.get("match","") in k:
                            STATE[k] = reset; log_timeseries(k, reset)
                elif act["type"] == "revoke_capabilities":
                    for aid, inst in APPS.items():
                        inst["caps"]["write"] = []
                elif act["type"] == "terminate_apps":
                    for aid in list(APPS.keys()):
                        stop_app_instance(aid)
        else:
            RISK["cooling_low_excess"] = False

MON_T = threading.Thread(target=monitor_loop, daemon=True)
MON_T.start()

# ---------------- App Steward (rate limiting + lifecycle) ----------------
def token_bucket_ok(inst: Dict) -> bool:
    now = time.time()
    bucket = inst.setdefault("rate", {"limit": inst["manifest"]["write_rate_limit_per_min"], "tokens": 0, "win": int(now//60)})
    if int(now//60) != bucket["win"]:
        bucket["win"] = int(now//60); bucket["tokens"] = 0
    if bucket["tokens"] >= bucket["limit"]:
        return False
    bucket["tokens"] += 1
    return True

def start_app_instance(man: Manifest) -> Dict:
    app_instance_id = f"{man.app_id}-{int(time.time()*1000)}"
    caps = compute_caps(man)
    APP_KEY = f"key_{app_instance_id}"
    env = os.environ.copy()
    env["SBOS_APP_KEY"] = APP_KEY
    env["SBOS_BASE"] = os.environ.get("SBOS_BASE", "http://localhost:8083")
    p = subprocess.Popen(["python3", "apps/comfort_app.py"], env=env)
    inst = {"manifest": man.__dict__, "pid": p.pid, "key": APP_KEY, "caps": caps, "user": man.user,
            "rate": {"limit": man.write_rate_limit_per_min, "tokens": 0, "win": int(time.time()//60)}}
    APPS[app_instance_id] = inst
    APP_KEYS[APP_KEY] = app_instance_id
    return {"app_instance_id": app_instance_id, "pid": p.pid, "key": APP_KEY}

def stop_app_instance(aid: str):
    inst = APPS.get(aid)
    if not inst: return
    try: os.kill(inst["pid"], signal.SIGTERM)
    except Exception: pass
    APP_KEYS.pop(inst["key"], None)
    APPS.pop(aid, None)

def list_instances():
    out = []
    for aid, inst in APPS.items():
        out.append({"id": aid, "pid": inst["pid"], "user": inst["user"],
                    "caps": {"read": [IRI2LABEL.get(i,i) for i in inst["caps"]["read"]],
                             "write":[IRI2LABEL.get(i,i) for i in inst["caps"]["write"]]}})
    return out

# ---------------- API Models ----------------
class ManifestIn(BaseModel):
    app_id: str
    profile: str
    args: Dict[str,str]
    delegation: str
    write_rate_limit_per_min: int = 60
    permissions: Dict[str,bool]
    user: str

class WriteReq(BaseModel):
    point_label: str
    value: float
    prev_value: Optional[float] = None

# ---------------- Auth ----------------
APPS: Dict[str, Dict] = APPS
APP_KEYS: Dict[str, str] = APP_KEYS

def get_app_instance_from_key(app_key: Optional[str]) -> Tuple[str,dict]:
    if not app_key:
        raise HTTPException(status_code=401, detail="Missing X-App-Key")
    aid = APP_KEYS.get(app_key)
    if not aid:
        raise HTTPException(status_code=403, detail="Invalid X-App-Key")
    return aid, APPS[aid]

# ---------------- Endpoints ----------------
@app.get("/health")
def health():
    return {"status": "ok", "risk": RISK}

@app.post("/admin/reload")
def admin_reload():
    load_all()
    for aid, inst in APPS.items():
        man = Manifest(**inst["manifest"])
        inst["caps"] = compute_caps(man)
    return {"ok": True}

@app.post("/admin/monitor")
def admin_monitor(enable: bool):
    global MON_RUNNING
    MON_RUNNING = enable
    return {"ok": True, "monitor": "running" if enable else "stopped"}

@app.get("/admin/txlog")
def admin_txlog(limit: int = 50):
    cur = DB.execute("SELECT ts,actor,app_id,user_id,action,point_label,value,decision,reason FROM txlog ORDER BY id DESC LIMIT ?", (limit,))
    return {"rows": cur.fetchall()}

@app.get("/admin/shadow_log")
def admin_shadow_log(limit: int = 50):
    cur = DB.execute("SELECT ts,app_id,user_id,point_label,value,cls,vtype,reason FROM shadowlog ORDER BY id DESC LIMIT ?", (limit,))
    return {"rows": cur.fetchall()}

@app.get("/admin/shadow_stats")
def admin_shadow_stats():
    cur = DB.execute("SELECT point_label, vtype, reason, COUNT(*) FROM shadowlog GROUP BY point_label, vtype, reason ORDER BY COUNT(*) DESC")
    return {"rows": cur.fetchall()}

@app.post("/admin/promote_shadow")
def admin_promote_shadow(resource_class: str):
    local = resource_class.split("#")[-1] if "#" in resource_class else resource_class
    cur = DB.execute("SELECT vtype FROM shadow_validators WHERE resource_class=? ORDER BY position ASC", (local,))
    sv = [r[0] for r in cur.fetchall()]
    if not sv:
        raise HTTPException(404, "No shadow validators to promote for class")
    cur2 = DB.execute("SELECT MAX(position) FROM validators WHERE resource_class=?", (local,))
    base = cur2.fetchone()[0] or -1
    with DB:
        for i, v in enumerate(sv):
            DB.execute("INSERT INTO validators(resource_class,position,vtype) VALUES(?,?,?)", (local, base+1+i, v))
    return {"ok": True, "promoted": sv, "class": local}

@app.post("/admin/app/register")
def register_app(manifest: ManifestIn):
    man = Manifest(**manifest.dict())
    info = start_app_instance(man)
    return info

@app.post("/admin/app/stop")
def admin_stop(aid: str):
    stop_app_instance(aid)
    return {"ok": True}

@app.get("/admin/app/list")
def admin_list():
    return list_instances()

@app.get("/capabilities")
def capabilities(x_app_key: Optional[str] = Header(default=None)):
    aid, inst = get_app_instance_from_key(x_app_key)
    pts = sorted(set(inst["caps"]["read"] + inst["caps"]["write"]))
    return {"app_instance": aid, "points": [{"iri": i, "label": IRI2LABEL.get(i,i)} for i in pts]}

@app.get("/read")
def read(point_label: str, x_app_key: Optional[str] = Header(default=None)):
    aid, inst = get_app_instance_from_key(x_app_key)
    iri = LABEL2IRI.get(point_label)
    if not iri:
        raise HTTPException(404, "Unknown point")
    if iri not in inst["caps"]["read"]:
        log_tx("app", aid, inst["user"], "read", iri, point_label, None, "deny", "no-cap-read")
        raise HTTPException(403, "No read capability")
    val = proxy_read(point_label)
    log_tx("app", aid, inst["user"], "read", iri, point_label, val, "allow", "ok")
    return {"point_label": point_label, "value": val}

@app.post("/write")
def write(req: WriteReq, x_app_key: Optional[str] = Header(default=None)):
    with UPDATE_LOCK:
        aid, inst = get_app_instance_from_key(x_app_key)
        if not token_bucket_ok(inst):
            raise HTTPException(429, "Write rate limit exceeded")
        iri = LABEL2IRI.get(req.point_label)
        if not iri:
            raise HTTPException(404, "Unknown point")
        if iri not in inst["caps"]["write"]:
            log_tx("app", aid, inst["user"], "write", iri, req.point_label, req.value, "deny", "no-cap-write")
            raise HTTPException(403, "No write capability")
        cls = class_of_iri(iri) or ""
        vlist = get_validators_for_class(cls)
        if not vlist:
            log_tx("regulator", aid, inst["user"], "write", iri, req.point_label, req.value, "deny", "no-validators")
            raise HTTPException(400, "No validators configured")
        prev = proxy_read(req.point_label)
        for vname in vlist:
            ok, reason = VALIDATOR_FUNS[vname](cls, req.point_label, req.value, prev)
            if not ok:
                log_tx("regulator", aid, inst["user"], "write", iri, req.point_label, req.value, "deny", reason)
                raise HTTPException(400, f"Guard blocked: {reason}")
        sv = get_shadow_validators_for_class(cls)
        for vname in sv:
            ok, reason = VALIDATOR_FUNS[vname](cls, req.point_label, req.value, prev)
            if not ok:
                log_shadow(aid, inst["user"], iri, req.point_label, req.value, cls, vname, reason)
        proxy_write(req.point_label, req.value)
        log_tx("proxy", aid, inst["user"], "write", iri, req.point_label, req.value, "allow", "ok")
        return {"ok": True, "point": req.point_label, "value": req.value}
