import time
import re
import sqlite3
from typing import List, Dict
from urllib.parse import unquote, unquote_plus
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
import httpx
import uvicorn

app = FastAPI(title="AEGIS Zero-Trust WAF & SOC Platform")

BACKEND_URL = "https://www.cyberarmy.it.com"
DB_FILE = "aegis_soc.db"
START_TIME = time.time()

ACTORS: Dict[str, Dict] = {}
active_connections: List[WebSocket] = []
DENYLIST: set = set()
ALLOWLIST: set = set()

HONEYPOT_NODES = [
    {"id": "node-1", "name": "Fake Admin Portal", "path": "/admin", "type": "Web Decoy", "status": "ACTIVE", "hits": 0},
    {"id": "node-2", "name": "WordPress Trap", "path": "/wp-login.php", "type": "CMS Decoy", "status": "ACTIVE", "hits": 0},
    {"id": "node-3", "name": "DB Manager Trap", "path": "/phpmyadmin", "type": "Database Decoy", "status": "ACTIVE", "hits": 0},
    {"id": "node-4", "name": "Secret Env Trap", "path": "/.env", "type": "Credential Decoy", "status": "ACTIVE", "hits": 0},
    {"id": "node-5", "name": "Config Trap", "path": "/config.json", "type": "Configuration Decoy", "status": "ACTIVE", "hits": 0}
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, client_ip TEXT, method TEXT, path TEXT,
        status TEXT, score INTEGER, severity TEXT, category TEXT, reason TEXT, is_demo INTEGER DEFAULT 0
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, operator TEXT, action TEXT, target TEXT, outcome TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_rules (
        id TEXT PRIMARY KEY, name TEXT, category TEXT, severity TEXT, pattern TEXT, description TEXT, enabled INTEGER DEFAULT 1
    )
    """)
    cursor.execute("SELECT COUNT(*) FROM waf_rules")
    if cursor.fetchone()[0] == 0:
        default_rules = [
            ("RULE-SQLI-01", "Classic SQLi Detection", "SQL Injection", "HIGH", r"(\bOR\b|\bAND\b)\s+['\"].*?['\"]?\s*=\s*['\"]?.*?|--|1=1|\bUNION\b\s+\bSELECT\b", "Blocks SQL injection patterns", 1),
            ("RULE-XSS-01", "Cross-Site Scripting Filter", "XSS", "HIGH", r"<script.*?>.*?</script.*?>|onerror\s*=|onload\s*=|alert\s*\(|<img\b[^>]*>|<svg\b[^>]*>", "Detects script tags and event handlers", 1),
            ("RULE-TRAV-01", "Path Traversal Detection", "Path Traversal", "HIGH", r"(\.\./|\.\.\\|etc/passwd|windows/win.ini)", "Prevents directory escaping", 1),
            ("RULE-METH-01", "Suspicious HTTP Method", "Method Policy", "MEDIUM", r"^(TRACK|TRACE|DEBUG)$", "Restricts unsafe HTTP verbs", 1)
        ]
        cursor.executemany("INSERT INTO waf_rules VALUES (?, ?, ?, ?, ?, ?, ?)", default_rules)
    conn.commit()
    conn.close()

init_db()

def get_actor_state(ip: str) -> Dict:
    now = time.time()
    if ip not in ACTORS:
        ACTORS[ip] = {"score": 0, "timestamps": [], "quarantined": False, "reason": "Clean"}
    ACTORS[ip]["timestamps"] = [t for t in ACTORS[ip]["timestamps"] if now - t < 10.0]
    return ACTORS[ip]

def log_audit(operator: str, action: str, target: str, outcome: str):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO audit_logs (timestamp, operator, action, target, outcome) VALUES (datetime('now', 'localtime'), ?, ?, ?, ?)", (operator, action, target, outcome))
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_event(client_ip: str, method: str, path: str, status: str, score: int, severity: str, category: str, reason: str, is_demo: int = 0):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO security_events (timestamp, client_ip, method, path, status, score, severity, category, reason, is_demo)
        VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (client_ip, method, path, status, score, severity, category, reason, is_demo))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_active_rules():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, category, severity, pattern, enabled FROM waf_rules WHERE enabled = 1")
    rules = cursor.fetchall()
    conn.close()
    return rules

async def broadcast_telemetry(payload: dict):
    dead = []
    for ws in active_connections:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for d in dead:
        if d in active_connections:
            active_connections.remove(d)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error loading index.html: {str(e)}</h3>", status_code=500)

@app.post("/api/unban")
def unban_ip(payload: Dict[str, str]):
    ip = payload.get("ip")
    if ip and ip in ACTORS:
        ACTORS[ip]["quarantined"] = False
        ACTORS[ip]["score"] = 0
        ACTORS[ip]["timestamps"] = []
    if ip and ip in DENYLIST:
        DENYLIST.remove(ip)
    log_audit("Admin", "RELEASE_QUARANTINE", ip, "SUCCESS")
    return {"status": "unbanned", "ip": ip}

@app.post("/api/quarantine/reset-all")
def reset_all_quarantine():
    ACTORS.clear()
    DENYLIST.clear()
    log_audit("Admin", "RESET_ALL_QUARANTINES", "ALL_ACTORS", "SUCCESS")
    return {"status": "cleared"}

@app.get("/api/system/health")
def get_system_health():
    uptime_sec = int(time.time() - START_TIME)
    return {
        "status": "HEALTHY",
        "uptime": f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m {uptime_sec % 60}s",
        "database": "SQLite (Connected)",
        "active_ws_clients": len(active_connections),
        "upstream_backend": BACKEND_URL,
        "protected_mode": "Zero-Trust Active Enforcement"
    }

@app.get("/api/quarantined")
def get_quarantined_actors():
    result = []
    for ip, data in ACTORS.items():
        if data.get("quarantined") or data.get("score", 0) >= 100 or ip in DENYLIST:
            result.append({"ip": ip, "score": data.get("score", 100), "reason": data.get("reason", "Suspicious Activity"), "status": "QUARANTINED"})
    return result

@app.get("/api/honeypot/nodes")
def get_honeypots():
    return HONEYPOT_NODES

@app.post("/api/honeypot/toggle")
def toggle_honeypot(payload: Dict[str, str]):
    node_id = payload.get("id")
    for node in HONEYPOT_NODES:
        if node["id"] == node_id:
            node["status"] = "INACTIVE" if node["status"] == "ACTIVE" else "ACTIVE"
            return {"status": "success", "node": node}
    raise HTTPException(status_code=404, detail="Honeypot not found")

@app.get("/api/rules")
def get_rules():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, category, severity, pattern, description, enabled FROM waf_rules")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "category": r[2], "severity": r[3], "pattern": r[4], "description": r[5], "enabled": bool(r[6])} for r in rows]

@app.post("/api/rules/toggle")
def toggle_rule(payload: Dict[str, str]):
    rule_id = payload.get("id")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM waf_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")
    new_state = 0 if row[0] == 1 else 1
    cursor.execute("UPDATE waf_rules SET enabled = ? WHERE id = ?", (new_state, rule_id))
    conn.commit()
    conn.close()
    return {"status": "success", "id": rule_id, "enabled": bool(new_state)}

@app.post("/api/rules/test")
def test_rule_sandbox(payload: Dict[str, str]):
    test_input = unquote_plus(unquote(payload.get("input", "")))
    for r_id, name, cat, sev, pattern, _ in get_active_rules():
        if re.search(pattern, test_input, re.IGNORECASE):
            return {"verdict": "BLOCKED", "rule_name": name, "category": cat, "severity": sev, "explain": f"Pattern matched regex: {pattern}"}
    return {"verdict": "ALLOWED", "explain": "Payload passed through cleanly."}

@app.get("/api/ip/reputation")
def get_ip_reputation(ip: str):
    actor = ACTORS.get(ip, {"score": 0, "timestamps": [], "quarantined": False, "reason": "No prior records"})
    cat = "CRITICAL / BOTNET" if actor["score"] >= 80 or ip in DENYLIST else ("SUSPICIOUS" if actor["score"] >= 40 else "CLEAN")
    return {"ip": ip, "score": actor["score"], "threat_category": cat, "is_denylisted": ip in DENYLIST, "is_allowlisted": ip in ALLOWLIST, "reputation_source": "Autonomous AEGIS L7 Behavioral Matrix"}

@app.get("/api/audit/logs")
def get_audit_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, operator, action, target, outcome FROM audit_logs ORDER BY id DESC LIMIT 50")
    logs = cursor.fetchall()
    conn.close()
    return [{"timestamp": l[0], "operator":