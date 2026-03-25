"""
ShieldWAF — Serveur principal FastAPI
- Proxy inverse : intercepte le trafic vers votre app
- API REST      : gestion des règles, logs, stats
"""
import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from waf.engine import WAFEngine
from waf.models import Request as WAFRequest, Action






# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

CONFIG = {
    "target_url":             "http://localhost:8080",  # Votre app à protéger
    "api_token":              "waf-secret-token-changez-moi",
    "rule_sql_injection":     True,
    "rule_xss":               True,
    "rule_path_traversal":    True,
    "rule_rfi":               True,
    "rule_command_injection": True,
    "block_scanners":         True,
    "rate_limit_enabled":     True,
    "rate_limit_max":         100,
    "rate_limit_window":      60,
}

engine = WAFEngine(CONFIG)
engine.add_ip_rule("185.220.101.47", "block", "Scanner TOR connu")
engine.add_ip_rule("45.33.32.156",   "block", "Tentatives SQLi")
engine.add_ip_rule("127.0.0.1",      "allow", "Localhost")
engine.add_ip_rule("192.168.0.0/16", "allow", "Réseau local")

app = FastAPI(title="ShieldWAF API", version="1.0.0", docs_url="/waf/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer()

def require_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds.credentials != CONFIG["api_token"]:
        raise HTTPException(401, "Token invalide")
    return creds.credentials

# ─────────────────────────────────────────
# PROXY INVERSE — filtre tout le trafic
# ─────────────────────────────────────────

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    if request.url.path.startswith("/waf/") or request.url.path == "/" or request.url.path.endswith(".html"):
        return await call_next(request)

    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="replace")

    waf_req = WAFRequest(
        client_ip=request.client.host or "unknown",
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        query_string=str(request.url.query) or None,
        body=body or None,
    )

    decision = engine.analyze(waf_req)

    if decision.action == Action.BLOCK:
        return Response(
            content=f'{{"error":"Forbidden","threat":"{decision.threat}","detail":"{decision.detail}"}}',
            status_code=403,
            media_type="application/json",
            headers={"X-WAF-Action": "block", "X-WAF-Threat": str(decision.threat)},
        )

    response = await call_next(request)
    if decision.action == Action.WARN:
        response.headers["X-WAF-Action"] = "warn"
        response.headers["X-WAF-Score"] = str(decision.score)
    return response


@app.get("/")
def serve_dashboard():
    return FileResponse("waf-dashboard.html")

# ─────────────────────────────────────────
# API REST
# ─────────────────────────────────────────

@app.get("/waf/stats")
def get_stats(token: str = Depends(require_auth)):
    blocked = [l for l in engine.logs if l.action == "block"]
    top_threats: dict = {}
    top_ips: dict = {}
    for l in blocked:
        if l.threat: top_threats[l.threat] = top_threats.get(l.threat, 0) + 1
        top_ips[l.client_ip] = top_ips.get(l.client_ip, 0) + 1
    return {
        "total_requests": engine.stats["total_requests"],
        "blocked":  engine.stats.get("block", 0),
        "allowed":  engine.stats.get("allow", 0),
        "warned":   engine.stats.get("warn", 0),
        "top_threats": sorted(top_threats.items(), key=lambda x: -x[1])[:5],
        "top_ips":     sorted(top_ips.items(), key=lambda x: -x[1])[:5],
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/waf/logs")
def get_logs(
    limit: int = 100,
    action: Optional[str] = None,
    ip: Optional[str] = None,
    threat: Optional[str] = None,
    token: str = Depends(require_auth),
):
    logs = engine.logs
    if action: logs = [l for l in logs if l.action == action]
    if ip:     logs = [l for l in logs if l.client_ip == ip]
    if threat: logs = [l for l in logs if l.threat == threat]
    return {"logs": [vars(l) for l in logs[:limit]], "total": len(logs)}

class IPRuleBody(BaseModel):
    ip: str
    type: str
    reason: Optional[str] = ""

@app.get("/waf/ips")
def get_ips(token: str = Depends(require_auth)):
    return {
        "rules": [{"ip": ip, "type": rule, "reason": engine.ip_reasons.get(ip, "")}
                  for ip, rule in engine.ip_rules.items()],
        "total": len(engine.ip_rules),
    }

@app.post("/waf/ips", status_code=201)
def add_ip(body: IPRuleBody, token: str = Depends(require_auth)):
    if body.type not in ("block", "allow", "warn"):
        raise HTTPException(400, "type doit être: block | allow | warn")
    engine.add_ip_rule(body.ip, body.type, body.reason or "")
    return {"ip": body.ip, "type": body.type, "created_at": datetime.utcnow().isoformat()}

@app.delete("/waf/ips/{ip:path}")
def delete_ip(ip: str, token: str = Depends(require_auth)):
    if not engine.remove_ip_rule(ip):
        raise HTTPException(404, f"IP non trouvée: {ip}")
    return {"deleted": True, "ip": ip}

RULE_NAMES = {
    "sql_injection": "Injection SQL", "xss": "Cross-Site Scripting",
    "path_traversal": "Path Traversal", "rfi": "Remote File Inclusion",
    "command_injection": "Injection de commandes",
}

@app.get("/waf/rules")
def get_rules(token: str = Depends(require_auth)):
    return {"rules": [{"id": k, "name": v, "enabled": CONFIG.get(f"rule_{k}", True)}
                      for k, v in RULE_NAMES.items()]}

class RuleUpdate(BaseModel):
    enabled: bool

@app.put("/waf/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, token: str = Depends(require_auth)):
    key = f"rule_{rule_id}"
    if key not in CONFIG:
        raise HTTPException(404, f"Règle inconnue: {rule_id}")
    CONFIG[key] = body.enabled
    engine.config[key] = body.enabled
    return {"id": rule_id, "enabled": body.enabled, "updated_at": datetime.utcnow().isoformat()}

class AnalyzeBody(BaseModel):
    ip: str = "127.0.0.1"
    method: str = "GET"
    path: str = "/"
    query_string: Optional[str] = None
    body: Optional[str] = None
    headers: Optional[dict] = None

@app.post("/waf/analyze")
def analyze_request(body: AnalyzeBody, token: str = Depends(require_auth)):
    """Tester une requête sans la transmettre."""
    waf_req = WAFRequest(
        client_ip=body.ip, method=body.method, path=body.path,
        headers=body.headers or {}, query_string=body.query_string, body=body.body,
    )
    d = engine.analyze(waf_req)
    return {"action": d.action.value, "threat": d.threat.value if d.threat else None,
            "score": d.score, "detail": d.detail}

if __name__ == "__main__":
    print("🛡  ShieldWAF sur http://0.0.0.0:8000")
    print("📖  Docs API  : http://localhost:8000/waf/docs")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
