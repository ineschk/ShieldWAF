"""Modèles de données ShieldWAF"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN  = "warn"


class ThreatType(str, Enum):
    SQL_INJECTION      = "sql_injection"
    XSS                = "xss"
    PATH_TRAVERSAL     = "path_traversal"
    RFI                = "rfi"
    COMMAND_INJECTION  = "command_injection"
    SCANNER            = "scanner"
    RATE_LIMIT         = "rate_limit"
    IP_BLACKLIST       = "ip_blacklist"


@dataclass
class Request:
    client_ip:    str
    method:       str
    path:         str
    headers:      dict
    query_string: Optional[str] = None
    body:         Optional[str] = None


@dataclass
class Decision:
    action: Action
    threat: Optional[ThreatType]
    score:  int
    detail: str = ""


@dataclass
class LogEntry:
    timestamp:   str
    client_ip:   str
    method:      str
    path:        str
    action:      str
    score:       int
    status_code: int
    threat:      Optional[str] = None
    detail:      str = ""
