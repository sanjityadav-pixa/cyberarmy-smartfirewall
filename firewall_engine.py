import time
import re
from typing import List, Dict
from urllib.parse import unquote_plus, unquote
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
import httpx
import uvicorn

app = FastAPI(title="Smart Reverse Proxy Firewall Engine")

# ==========================================
# CONFIGURATION & STATE
# ==========================================
BACKEND_URL = "http://127.0.0.1:9000"

ACTORS: Dict[str, Dict] = {}
active_connections: List[WebSocket] = []

SQLI_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"].*?['\"]?\s*=\s*['\"]?.*?",
    r"--",
    r"/\*.*?\*/",
    r"\bUNION\b\s+\bSELECT\b",
    r"\bSELECT\b.*?\bFROM\b",
    r"\bDROP\b\s+\bTABLE\b",
    r"1=1"
]

# Bullet-proof XSS Signatures
XSS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror",
    r"oneerror",               # Typo bypass fix
    r"onload",
    r"alert\s*\(",             # Direct alert('XSS') match
    r"<img\b",                 # Direct match for ANY <img tag regardless of attributes
    r"<svg\b",
    r"<iframe\b",
    r"<body\b"
]

HONEYPOT_PATHS = [
    "/admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/setup.php",
    "/.env",
    "/config.json"
]

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def get_actor_state(ip: str) -> Dict:
    now = time.time()
    if ip not in ACTORS:
        ACTORS[ip] = {
            "score": 0,
            "timestamps": [],
            "quarantined": False
        }
    ACTORS[ip]["timestamps"] = [t for t in ACTORS[ip]["timestamps"] if now - t < 10.0]
    return ACTORS[ip]

async def broadcast_telemetry(payload: dict):
    dead_connections = []
    for ws in active_connections:
        try:
            await ws.send_json(payload)
        except Exception:
            dead_connections.append(ws)
    for dc in dead_connections:
        if dc in active_connections:
            active_connections.remove(dc)

# ==========================================
# WEBSOCKET & DASHBOARD ENDPOINTS
# ==========================================
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

# --- YAHAN PASTE KAREIN (A wala code) ---
@app.post("/api/unquarantine")
async def unquarantine_ip(data: dict):
    target_ip = data.get("ip")
    if target_ip in quarantined_ips:
        quarantined_ips.remove(target_ip)
    if target_ip in attacker_scores:
        attacker_scores[target_ip] = 0
    await manager.broadcast({
        "action": "UNQUARANTINE",
        "client_ip": target_ip
    })
    return {"status": "success", "message": f"{target_ip} has been released"}

# ==========================================
# L7 FIREWALL MIDDLEWARE
# ==========================================
@app.middleware("http")
async def firewall_middleware(request: Request, call_next):
    # 1. Dashboard, WebSocket bypass
    if request.url.path in ["/ws", "/dashboard", "/favicon.ico"]:
        return await call_next(request)

    client_ip = request.client.host if request.client else "127.0.0.1"
    actor = get_actor_state(client_ip)
    now = time.time()
    actor["timestamps"].append(now)

    req_path = request.url.path
    query_str = str(request.url.query)
    raw_query = request.scope.get("query_string", b"").decode("utf-8", errors="ignore")
    method = request.method

    country_badge = "IN"
    network_origin = "LOCAL/INT"

    # 2. Check if already quarantined
    if actor["quarantined"] or actor["score"] >= 100:
        actor["quarantined"] = True
        event = {
            "client_ip": client_ip,
            "country": country_badge,
            "origin": network_origin,
            "method": method,
            "path": req_path,
            "status": "BLOCKED",
            "score": actor["score"],
            "reason": "Host Quarantined (Score >= 100)"
        }
        await broadcast_telemetry(event)
        return JSONResponse(
            status_code=403,
            content={"error": "Access Denied by WAF: Endpoint Quarantined", "ip": client_ip, "score": actor["score"]}
        )

    # 3. Honeypot Path Inspection
    for trap in HONEYPOT_PATHS:
        if req_path.lower() == trap.lower() or req_path.lower().startswith(trap.lower()):
            actor["score"] = 100
            actor["quarantined"] = True
            event = {
                "client_ip": client_ip,
                "country": country_badge,
                "origin": network_origin,
                "method": method,
                "path": req_path,
                "status": "BLOCKED",
                "score": 100,
                "reason": f"Honeypot Trap Triggered ({trap})"
            }
            await broadcast_telemetry(event)
            return JSONResponse(
                status_code=403,
                content={"error": "Critical Intrusion Detected: Honeypot Triggered", "ip": client_ip, "score": 100}
            )

    # 4. Layer 7 Signature Inspection with Multi-stage Decoding
    # Normal and plus-decoded inspection string
    combined_raw = f"{req_path} {query_str} {raw_query}"
    decoded_string = unquote_plus(unquote(combined_raw))

    # Debug print console par dekhne ke liye
    print(f"\n[INSPECTING] Raw: {combined_raw}")
    print(f"[INSPECTING] Decoded: {decoded_string}\n")

    # SQL Injection Check
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, decoded_string, re.IGNORECASE) or re.search(pattern, combined_raw, re.IGNORECASE):
            actor["score"] = min(100, actor["score"] + 45)
            if actor["score"] >= 100:
                actor["quarantined"] = True

            event = {
                "client_ip": client_ip,
                "country": country_badge,
                "origin": network_origin,
                "method": method,
                "path": req_path,
                "status": "BLOCKED",
                "score": actor["score"],
                "reason": "SQL Injection Signature Detected"
            }
            await broadcast_telemetry(event)
            return JSONResponse(
                status_code=403,
                content={"error": "L7 WAF: SQL Injection Intercepted", "score": actor["score"]}
            )

    # XSS Check
    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded_string, re.IGNORECASE) or re.search(pattern, combined_raw, re.IGNORECASE):
            actor["score"] = min(100, actor["score"] + 40)
            if actor["score"] >= 100:
                actor["quarantined"] = True

            event = {
                "client_ip": client_ip,
                "country": country_badge,
                "origin": network_origin,
                "method": method,
                "path": req_path,
                "status": "BLOCKED",
                "score": actor["score"],
                "reason": "XSS Script Injection Detected"
            }
            await broadcast_telemetry(event)
            return JSONResponse(
                status_code=403,
                content={"error": "L7 WAF: Cross-Site Scripting Blocked", "score": actor["score"]}
            )

    # 5. Rate Limiting Check
    recent_reqs = [t for t in actor["timestamps"] if now - t < 5.0]
    if len(recent_reqs) > 15:
        actor["score"] = min(100, actor["score"] + 25)
        if actor["score"] >= 100:
            actor["quarantined"] = True

        event = {
            "client_ip": client_ip,
            "country": country_badge,
            "origin": network_origin,
            "method": method,
            "path": req_path,
            "status": "BLOCKED",
            "score": actor["score"],
            "reason": "Rate-Limit Exceeded (DoS Flooding)"
        }
        await broadcast_telemetry(event)
        return JSONResponse(
            status_code=429,
            content={"error": "Rate Limit Exceeded: Slow down", "score": actor["score"]}
        )

    # 6. Normal Clean Traffic (Forwarding)
    event = {
        "client_ip": client_ip,
        "country": country_badge,
        "origin": network_origin,
        "method": method,
        "path": req_path,
        "status": "ALLOWED",
        "score": actor["score"],
        "reason": "VERIFIED CLEAN"
    }
    await broadcast_telemetry(event)

    target_backend_url = f"{BACKEND_URL}{request.url.path}"
    if request.url.query:
        target_backend_url += f"?{request.url.query}"

    try:
        async with httpx.AsyncClient() as client:
            backend_resp = await client.request(
                method=request.method,
                url=target_backend_url,
                headers=dict(request.headers),
                content=await request.body(),
                timeout=5.0
            )
            return Response(
                content=backend_resp.content,
                status_code=backend_resp.status_code,
                headers=dict(backend_resp.headers)
            )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={"error": "Bad Gateway: Protected backend on port 9000 is not reachable."}
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Proxy Error: {str(e)}"})

# ==========================================
# RUN SERVER
# ==========================================
if __name__ == "__main__":
    uvicorn.run("firewall_engine:app", host="0.0.0.0", port=8080, reload=False)