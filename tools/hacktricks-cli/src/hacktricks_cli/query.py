import difflib
import importlib.resources
import json
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional


@dataclass
class Command:
    name: str
    category: str
    command: str
    note: str = ""
    platform: str = "both"  # "linux", "windows", "both"


@dataclass
class Service:
    slug: str
    name: str
    full_name: str
    ports: list[int]
    description: str
    commands: list[Command] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)


@dataclass
class Technique:
    slug: str
    name: str
    full_name: str
    description: str
    phase: str
    mitre: str
    required_access: str
    commands: list[Command] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)


@dataclass
class PostexTechnique:
    slug: str
    name: str
    full_name: str
    description: str
    topic: str
    platform: str
    commands: list[Command] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)


@dataclass
class PrivescTechnique:
    slug: str
    name: str
    full_name: str
    description: str
    platform: str  # "linux", "windows", or "both"
    commands: list[Command] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)


@dataclass
class Payload:
    context: str
    payload: str
    note: str = ""


@dataclass
class WebVulnTechnique:
    slug: str
    name: str
    full_name: str
    description: str
    vuln_type: str
    payloads: list[Payload] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)


# ── Index loaders ──────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "index.json"
    return json.loads(data_file.read_text())


@lru_cache(maxsize=1)
def _load_ad_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "ad_techniques.json"
    try:
        return json.loads(data_file.read_text())
    except Exception:
        return {"techniques": {}}


@lru_cache(maxsize=1)
def _load_postex_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "postex.json"
    try:
        return json.loads(data_file.read_text())
    except Exception:
        return {"techniques": {}, "topic_index": {}}


@lru_cache(maxsize=1)
def _load_privesc_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "privesc.json"
    try:
        return json.loads(data_file.read_text())
    except Exception:
        return {"techniques": {}, "platform_index": {}}


@lru_cache(maxsize=1)
def _load_web_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "web_vulns.json"
    try:
        return json.loads(data_file.read_text())
    except Exception:
        return {"techniques": {}, "type_index": {}}


# ── Parsers ────────────────────────────────────────────────────────────────────

def _parse_service(slug: str, raw: dict) -> Service:
    commands = [
        Command(
            name=c.get("name", ""),
            category=c.get("category", "enumeration"),
            command=c.get("command", ""),
            note=c.get("note", ""),
        )
        for c in raw.get("commands", [])
        if c.get("command")
    ]
    return Service(
        slug=slug,
        name=raw.get("name", slug.upper()),
        full_name=raw.get("full_name", raw.get("name", slug)),
        ports=raw.get("ports", []),
        description=raw.get("description", ""),
        commands=commands,
        aliases=raw.get("aliases", []),
        see_also=raw.get("see_also", []),
    )


def _parse_privesc(slug: str, raw: dict) -> PrivescTechnique:
    commands = [
        Command(
            name=c.get("name", ""),
            category=c.get("category", "enumeration"),
            command=c.get("command", ""),
            note=c.get("note", ""),
            platform=c.get("platform", "both"),
        )
        for c in raw.get("commands", [])
        if c.get("command")
    ]
    return PrivescTechnique(
        slug=slug,
        name=raw.get("name", slug),
        full_name=raw.get("full_name", raw.get("name", slug)),
        description=raw.get("description", ""),
        platform=raw.get("platform", "both"),
        commands=commands,
        aliases=raw.get("aliases", []),
        see_also=raw.get("see_also", []),
    )


def _parse_postex(slug: str, raw: dict) -> PostexTechnique:
    commands = [
        Command(
            name=c.get("name", ""),
            category=c.get("category", "post-exploitation"),
            command=c.get("command", ""),
            note=c.get("note", ""),
            platform=c.get("platform", "both"),
        )
        for c in raw.get("commands", [])
        if c.get("command")
    ]
    return PostexTechnique(
        slug=slug,
        name=raw.get("name", slug),
        full_name=raw.get("full_name", raw.get("name", slug)),
        description=raw.get("description", ""),
        topic=raw.get("topic", ""),
        platform=raw.get("platform", "both"),
        commands=commands,
        aliases=raw.get("aliases", []),
        see_also=raw.get("see_also", []),
    )


def _parse_web(slug: str, raw: dict) -> WebVulnTechnique:
    payloads = [
        Payload(
            context=p.get("context", ""),
            payload=p.get("payload", ""),
            note=p.get("note", ""),
        )
        for p in raw.get("payloads", [])
        if p.get("payload")
    ]
    commands = [
        Command(
            name=c.get("name", ""),
            category=c.get("category", "exploitation"),
            command=c.get("command", ""),
            note=c.get("note", ""),
            platform=c.get("platform", "both"),
        )
        for c in raw.get("commands", [])
        if c.get("command")
    ]
    return WebVulnTechnique(
        slug=slug,
        name=raw.get("name", slug),
        full_name=raw.get("full_name", raw.get("name", slug)),
        description=raw.get("description", ""),
        vuln_type=raw.get("vuln_type", "misc"),
        payloads=payloads,
        commands=commands,
        aliases=raw.get("aliases", []),
        see_also=raw.get("see_also", []),
    )


def _parse_technique(slug: str, raw: dict) -> Technique:
    commands = [
        Command(
            name=c.get("name", ""),
            category=c.get("category", "enumeration"),
            command=c.get("command", ""),
            note=c.get("note", ""),
            platform=c.get("platform", "both"),
        )
        for c in raw.get("commands", [])
        if c.get("command")
    ]
    return Technique(
        slug=slug,
        name=raw.get("name", slug.upper()),
        full_name=raw.get("full_name", raw.get("name", slug)),
        description=raw.get("description", ""),
        phase=raw.get("phase", ""),
        mitre=raw.get("mitre") or "",
        required_access=raw.get("required_access", ""),
        commands=commands,
        aliases=raw.get("aliases", []),
        see_also=raw.get("see_also", []),
    )


# ── Service queries ────────────────────────────────────────────────────────────

def query_port(port: int) -> list[Service]:
    index = _load_index()
    slugs = index["port_index"].get(str(port), [])
    return [_parse_service(s, index["services"][s]) for s in slugs if s in index["services"]]


def query_service(name: str) -> Optional[Service]:
    index = _load_index()
    name_lower = name.lower()

    if name_lower in index["services"]:
        return _parse_service(name_lower, index["services"][name_lower])

    candidates = {}
    for slug, raw in index["services"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_service(slug, index["services"][slug])

    all_terms = [(term, slug) for slug, terms in candidates.items() for term in terms]
    term_strings = [t[0] for t in all_terms]
    close = difflib.get_close_matches(name_lower, term_strings, n=1, cutoff=0.6)
    if close:
        matched_term = close[0]
        for term, slug in all_terms:
            if term == matched_term:
                return _parse_service(slug, index["services"][slug])

    return None


def list_all() -> list[Service]:
    index = _load_index()
    return sorted(
        [_parse_service(slug, raw) for slug, raw in index["services"].items()],
        key=lambda s: s.ports[0] if s.ports else 0,
    )


def index_meta() -> dict:
    index = _load_index()
    ad_index = _load_ad_index()
    return {
        "version": index.get("version"),
        "generated_at": index.get("generated_at"),
        "source_commit": index.get("source_commit"),
        "service_count": len(index.get("services", {})),
        "port_count": len(index.get("port_index", {})),
        "ad_technique_count": len(ad_index.get("techniques", {})),
    }


# ── Technique queries ──────────────────────────────────────────────────────────

_PHASE_ORDER = [
    "enumeration",
    "credential-access",
    "lateral-movement",
    "privilege-escalation",
    "persistence",
]


def query_technique(name: str) -> Optional[Technique]:
    index = _load_ad_index()
    name_lower = name.lower()

    if name_lower in index["techniques"]:
        return _parse_technique(name_lower, index["techniques"][name_lower])

    candidates = {}
    for slug, raw in index["techniques"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_technique(slug, index["techniques"][slug])

    all_terms = [(term, slug) for slug, terms in candidates.items() for term in terms]
    term_strings = [t[0] for t in all_terms]
    close = difflib.get_close_matches(name_lower, term_strings, n=1, cutoff=0.6)
    if close:
        matched_term = close[0]
        for term, slug in all_terms:
            if term == matched_term:
                return _parse_technique(slug, index["techniques"][slug])

    return None


def list_all_techniques() -> list[Technique]:
    index = _load_ad_index()
    return sorted(
        [_parse_technique(slug, raw) for slug, raw in index["techniques"].items()],
        key=lambda t: (_PHASE_ORDER.index(t.phase) if t.phase in _PHASE_ORDER else len(_PHASE_ORDER), t.name),
    )


# ── Postex queries ─────────────────────────────────────────────────────────────

POSTEX_TOPICS = ["exfiltration", "tunneling", "brute-force", "search-exploits"]

_TOPIC_ALIASES: dict[str, str] = {
    "exfil": "exfiltration",
    "tunnel": "tunneling",
    "port-forward": "tunneling",
    "portforward": "tunneling",
    "port-forwarding": "tunneling",
    "brute": "brute-force",
    "bruteforce": "brute-force",
    "brute force": "brute-force",
    "searchsploit": "search-exploits",
    "exploit-db": "search-exploits",
    "exploitdb": "search-exploits",
    "search-exploit": "search-exploits",
    "search exploits": "search-exploits",
}


def _resolve_topic(name: str) -> Optional[str]:
    n = name.lower().strip()
    if n in POSTEX_TOPICS:
        return n
    return _TOPIC_ALIASES.get(n)


def query_postex(name: str) -> Optional[PostexTechnique]:
    index = _load_postex_index()
    name_lower = name.lower()

    if name_lower in index["techniques"]:
        return _parse_postex(name_lower, index["techniques"][name_lower])

    candidates: dict[str, list[str]] = {}
    for slug, raw in index["techniques"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_postex(slug, index["techniques"][slug])

    all_terms = [(term, slug) for slug, terms in candidates.items() for term in terms]
    term_strings = [t[0] for t in all_terms]
    close = difflib.get_close_matches(name_lower, term_strings, n=1, cutoff=0.6)
    if close:
        matched_term = close[0]
        for term, slug in all_terms:
            if term == matched_term:
                return _parse_postex(slug, index["techniques"][slug])

    return None


def query_postex_topic(topic: str) -> list[PostexTechnique]:
    index = _load_postex_index()
    slugs = index.get("topic_index", {}).get(topic, [])
    return [
        _parse_postex(s, index["techniques"][s])
        for s in slugs
        if s in index["techniques"]
    ]


def list_all_postex() -> list[PostexTechnique]:
    index = _load_postex_index()
    return sorted(
        [_parse_postex(slug, raw) for slug, raw in index["techniques"].items()],
        key=lambda t: (t.topic, t.name),
    )


def postex_index_counts() -> dict[str, int]:
    index = _load_postex_index()
    topic_index = index.get("topic_index", {})
    return {topic: len(slugs) for topic, slugs in topic_index.items()}


# ── Privesc queries ────────────────────────────────────────────────────────────

PRIVESC_PLATFORMS = ["linux", "windows"]

_PLATFORM_ALIASES: dict[str, str] = {
    "win": "windows",
    "linux privesc": "linux",
    "windows privesc": "windows",
    "privesc linux": "linux",
    "privesc windows": "windows",
    "privesc win": "windows",
    "lpe linux": "linux",
    "lpe windows": "windows",
    "lpe win": "windows",
}


def _resolve_privesc_platform(name: str) -> Optional[str]:
    n = name.lower().strip()
    if n in PRIVESC_PLATFORMS:
        return n
    return _PLATFORM_ALIASES.get(n)


def query_privesc(name: str) -> Optional[PrivescTechnique]:
    index = _load_privesc_index()
    name_lower = name.lower()

    if name_lower in index["techniques"]:
        return _parse_privesc(name_lower, index["techniques"][name_lower])

    candidates: dict[str, list[str]] = {}
    for slug, raw in index["techniques"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_privesc(slug, index["techniques"][slug])

    all_terms = [(term, slug) for slug, terms in candidates.items() for term in terms]
    term_strings = [t[0] for t in all_terms]
    close = difflib.get_close_matches(name_lower, term_strings, n=1, cutoff=0.6)
    if close:
        matched_term = close[0]
        for term, slug in all_terms:
            if term == matched_term:
                return _parse_privesc(slug, index["techniques"][slug])

    return None


def query_privesc_platform(platform: str) -> list[PrivescTechnique]:
    index = _load_privesc_index()
    slugs = index.get("platform_index", {}).get(platform, [])
    return [
        _parse_privesc(s, index["techniques"][s])
        for s in slugs
        if s in index["techniques"]
    ]


def list_all_privesc() -> list[PrivescTechnique]:
    index = _load_privesc_index()
    return sorted(
        [_parse_privesc(slug, raw) for slug, raw in index["techniques"].items()],
        key=lambda t: (t.platform, t.name),
    )


def privesc_index_counts() -> dict[str, int]:
    index = _load_privesc_index()
    platform_index = index.get("platform_index", {})
    return {platform: len(slugs) for platform, slugs in platform_index.items()}


# ── Web vuln queries ───────────────────────────────────────────────────────────

WEB_VULN_TYPES = [
    "injection", "xss", "xxe", "ssrf", "ssti",
    "auth-bypass", "access-control", "request-manipulation",
    "file-based", "deserialization", "client-side", "misc",
]

_WEB_TYPE_ALIASES: dict[str, str] = {
    "sqli": "injection",
    "sql": "injection",
    "nosql": "injection",
    "ldap": "injection",
    "cmdi": "injection",
    "command injection": "injection",
    "command-injection": "injection",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "xml external entity": "xxe",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "server-side template injection": "ssti",
    "server side template injection": "ssti",
    "template injection": "ssti",
    "jwt": "auth-bypass",
    "oauth": "auth-bypass",
    "saml": "auth-bypass",
    "2fa": "auth-bypass",
    "idor": "access-control",
    "mass assignment": "access-control",
    "smuggling": "request-manipulation",
    "http smuggling": "request-manipulation",
    "cors": "request-manipulation",
    "csp": "request-manipulation",
    "lfi": "file-based",
    "rfi": "file-based",
    "path traversal": "file-based",
    "file upload": "file-based",
    "file inclusion": "file-based",
    "csrf": "client-side",
    "clickjacking": "client-side",
    "open redirect": "misc",
    "race condition": "misc",
    "websocket": "misc",
}


def _resolve_web_type(name: str) -> Optional[str]:
    n = name.lower().strip()
    if n in WEB_VULN_TYPES:
        return n
    return _WEB_TYPE_ALIASES.get(n)


def query_web(name: str) -> Optional[WebVulnTechnique]:
    index = _load_web_index()
    name_lower = name.lower()

    if name_lower in index["techniques"]:
        return _parse_web(name_lower, index["techniques"][name_lower])

    candidates: dict[str, list[str]] = {}
    for slug, raw in index["techniques"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_web(slug, index["techniques"][slug])

    all_terms = [(term, slug) for slug, terms in candidates.items() for term in terms]
    term_strings = [t[0] for t in all_terms]
    close = difflib.get_close_matches(name_lower, term_strings, n=1, cutoff=0.6)
    if close:
        matched_term = close[0]
        for term, slug in all_terms:
            if term == matched_term:
                return _parse_web(slug, index["techniques"][slug])

    return None


def query_web_type(vuln_type: str) -> list[WebVulnTechnique]:
    index = _load_web_index()
    slugs = index.get("type_index", {}).get(vuln_type, [])
    return [
        _parse_web(s, index["techniques"][s])
        for s in slugs
        if s in index["techniques"]
    ]


def list_all_web() -> list[WebVulnTechnique]:
    index = _load_web_index()
    return sorted(
        [_parse_web(slug, raw) for slug, raw in index["techniques"].items()],
        key=lambda t: (t.vuln_type, t.name),
    )


def web_index_counts() -> dict[str, int]:
    index = _load_web_index()
    type_index = index.get("type_index", {})
    return {vtype: len(slugs) for vtype, slugs in type_index.items()}
