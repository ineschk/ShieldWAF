"""
ShieldWAF — Moteur de filtrage principal
Analyse chaque requête HTTP et applique les règles de sécurité
"""
import re
import time
import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Optional
from .models import Request, Decision, Action, ThreatType, LogEntry


# ─────────────────────────────────────────
# RÈGLES DE DÉTECTION (patterns regex)
# ─────────────────────────────────────────

RULES = {
    ThreatType.SQL_INJECTION: [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
        r"(--|;|\/\*|\*\/)",
        r"(\bOR\b\s+\d+=\d+)",
        r"(\bAND\b\s+\d+=\d+)",
        r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
        r"(xp_cmdshell|exec\s*\(|execute\s*\()",
        r"('|\"|`)\s*(OR|AND)\s*('|\"|`)",
        r"(\bINFORMATION_SCHEMA\b|\bSYSTEM_USER\b)",
    ],
    ThreatType.XSS: [
        r"<script[\s\S]*?>[\s\S]*?<\/script>",
        r"javascript\s*:",
        r"on\w+\s*=\s*[\"']",
        r"<\s*(img|svg|iframe|object|embed)[^>]*(src|href)\s*=",
        r"document\.(cookie|write|location)",
        r"window\.(location|open)",
        r"eval\s*\(",
        r"expression\s*\(",
    ],
    ThreatType.PATH_TRAVERSAL: [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[%2f%5c]",
        r"(\/etc\/passwd|\/etc\/shadow|\/proc\/self)",
        r"(boot\.ini|win\.ini|system32)",
    ],
    ThreatType.RFI: [
        r"(https?|ftp):\/\/[^\s]+\.(php|txt|exe)",
        r"=https?:\/\/",
        r"include\s*\(\s*[\"']https?:\/\/",
    ],
    ThreatType.COMMAND_INJECTION: [
        r"[;&|`]\s*(ls|cat|whoami|id|uname|pwd|wget|curl|bash|sh|python|perl|ruby)",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"(\/bin\/|\/usr\/bin\/)",
    ],
    ThreatType.SCANNER: [
        # User-agents connus de scanners
    ],
}

MALICIOUS_USER_AGENTS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster",
    r"burpsuite", r"hydra", r"metasploit", r"acunetix",
    r"openvas", r"nessus", r"w3af", r"havij", r"pangolin",
]

SCANNER_PATHS = [
    r"\/wp-admin", r"\/phpmyadmin", r"\/\.env",
    r"\/config\.(php|yml|json)", r"\/backup",
    r"\/.git\/", r"\/vendor\/", r"\/\.htaccess",
]


# ─────────────────────────────────────────
# MOTEUR WAF
# ─────────────────────────────────────────

class WAFEngine:
    def __init__(self, config: dict):
        self.config = config
        self.ip_rules: dict[str, str] = {}      # ip -> "block" | "allow" | "warn"
        self.ip_reasons: dict[str, str] = {}
        self.rate_counters: dict[str, list] = defaultdict(list)
        self.logs: list[LogEntry] = []
        self.stats = {
            "total_requests": 0,
            "blocked": 0,
            "allowed": 0,
            "warned": 0,
        }
        # Compile les patterns pour la performance
        self._compiled = {
            threat: [re.compile(p, re.IGNORECASE) for p in patterns]
            for threat, patterns in RULES.items()
        }
        self._ua_patterns = [re.compile(p, re.IGNORECASE) for p in MALICIOUS_USER_AGENTS]
        self._scanner_paths = [re.compile(p, re.IGNORECASE) for p in SCANNER_PATHS]

    def analyze(self, req: Request) -> Decision:
        """Point d'entrée principal — analyse une requête et retourne une décision."""
        self.stats["total_requests"] += 1

        # 1. Vérification IP (whitelist / blacklist)
        ip_decision = self._check_ip(req.client_ip)
        if ip_decision:
            return self._log_and_return(req, ip_decision)

        # 2. Rate limiting
        rl_decision = self._check_rate_limit(req.client_ip)
        if rl_decision:
            return self._log_and_return(req, rl_decision)

        # 3. User-Agent malveillant
        ua_decision = self._check_user_agent(req)
        if ua_decision:
            return self._log_and_return(req, ua_decision)

        # 4. Chemin suspect (scanner)
        path_decision = self._check_path(req)
        if path_decision:
            return self._log_and_return(req, path_decision)

        # 5. Analyse du contenu (corps + paramètres)
        content_decision = self._check_content(req)
        if content_decision:
            return self._log_and_return(req, content_decision)

        # ✓ Requête propre
        decision = Decision(action=Action.ALLOW, threat=None, score=0)
        return self._log_and_return(req, decision)

    # ── Vérifications individuelles ──────

    def _check_ip(self, ip: str) -> Optional[Decision]:
        """Vérifie si l'IP est dans les règles manuelles ou les CIDRs."""
        # Exact match
        if ip in self.ip_rules:
            rule = self.ip_rules[ip]
            if rule == "block":
                return Decision(Action.BLOCK, ThreatType.IP_BLACKLIST, 100,
                                f"IP bloquée: {self.ip_reasons.get(ip,'')}")
            if rule == "allow":
                return Decision(Action.ALLOW, None, 0, "IP whitelistée")
            if rule == "warn":
                return Decision(Action.WARN, ThreatType.IP_BLACKLIST, 40,
                                f"IP surveillée: {self.ip_reasons.get(ip,'')}")

        # CIDR match
        try:
            client = ipaddress.ip_address(ip)
            for cidr, rule in self.ip_rules.items():
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if client in network:
                        if rule == "block":
                            return Decision(Action.BLOCK, ThreatType.IP_BLACKLIST, 100,
                                            f"Réseau bloqué: {cidr}")
                        if rule == "allow":
                            return Decision(Action.ALLOW, None, 0, f"Réseau autorisé: {cidr}")
                except ValueError:
                    pass
        except ValueError:
            pass
        return None

    def _check_rate_limit(self, ip: str) -> Optional[Decision]:
        """Limite de taux : max N requêtes par fenêtre de temps."""
        if not self.config.get("rate_limit_enabled", True):
            return None
        max_req = self.config.get("rate_limit_max", 100)
        window = self.config.get("rate_limit_window", 60)

        now = time.time()
        timestamps = self.rate_counters[ip]
        # Nettoyer les vieilles entrées
        self.rate_counters[ip] = [t for t in timestamps if now - t < window]
        self.rate_counters[ip].append(now)

        if len(self.rate_counters[ip]) > max_req:
            return Decision(Action.BLOCK, ThreatType.RATE_LIMIT, 80,
                            f"Rate limit dépassé: {len(self.rate_counters[ip])} req/{window}s")
        return None

    def _check_user_agent(self, req: Request) -> Optional[Decision]:
        if not self.config.get("block_scanners", True):
            return None
        ua = req.headers.get("user-agent", "").lower()
        for pattern in self._ua_patterns:
            if pattern.search(ua):
                return Decision(Action.BLOCK, ThreatType.SCANNER, 90,
                                f"Scanner détecté: {pattern.pattern}")
        return None

    def _check_path(self, req: Request) -> Optional[Decision]:
        if not self.config.get("block_scanners", True):
            return None
        for pattern in self._scanner_paths:
            if pattern.search(req.path):
                return Decision(Action.WARN, ThreatType.SCANNER, 50,
                                f"Chemin suspect: {req.path}")
        return None

    def _check_content(self, req: Request) -> Optional[Decision]:
        """Analyse le contenu de la requête contre toutes les règles."""
        targets = [
            req.path,
            req.query_string or "",
            req.body or "",
            *req.headers.values(),
        ]
        combined = " ".join(targets)

        best: Optional[Decision] = None
        for threat, patterns in self._compiled.items():
            rule_key = threat.value
            if not self.config.get(f"rule_{rule_key}", True):
                continue
            for pattern in patterns:
                if pattern.search(combined):
                    score = self._score(threat)
                    action = Action.BLOCK if score >= 70 else Action.WARN
                    d = Decision(action, threat, score,
                                 f"Pattern détecté: {pattern.pattern[:60]}")
                    if best is None or score > best.score:
                        best = d
        return best

    def _score(self, threat: ThreatType) -> int:
        scores = {
            ThreatType.SQL_INJECTION: 90,
            ThreatType.XSS: 85,
            ThreatType.COMMAND_INJECTION: 95,
            ThreatType.PATH_TRAVERSAL: 80,
            ThreatType.RFI: 85,
            ThreatType.SCANNER: 60,
            ThreatType.RATE_LIMIT: 80,
            ThreatType.IP_BLACKLIST: 100,
        }
        return scores.get(threat, 50)

    def _log_and_return(self, req: Request, decision: Decision) -> Decision:
        entry = LogEntry(
            timestamp=datetime.utcnow().isoformat(),
            client_ip=req.client_ip,
            method=req.method,
            path=req.path,
            threat=decision.threat.value if decision.threat else None,
            action=decision.action.value,
            score=decision.score,
            detail=decision.detail,
            status_code=self._status_code(decision.action),
        )
        self.logs.insert(0, entry)
        if len(self.logs) > 10000:
            self.logs = self.logs[:10000]

        self.stats[decision.action.value] = self.stats.get(decision.action.value, 0) + 1
        return decision

    def _status_code(self, action: Action) -> int:
        return {Action.BLOCK: 403, Action.WARN: 429, Action.ALLOW: 200}[action]

    # ── Gestion des règles IP ────────────

    def add_ip_rule(self, ip: str, rule: str, reason: str = ""):
        self.ip_rules[ip] = rule
        self.ip_reasons[ip] = reason

    def remove_ip_rule(self, ip: str) -> bool:
        if ip in self.ip_rules:
            del self.ip_rules[ip]
            self.ip_reasons.pop(ip, None)
            return True
        return False
