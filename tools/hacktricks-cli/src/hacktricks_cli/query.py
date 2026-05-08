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


@lru_cache(maxsize=1)
def _load_index() -> dict:
    pkg = importlib.resources.files("hacktricks_cli")
    data_file = pkg / "data" / "index.json"
    return json.loads(data_file.read_text())


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


def query_port(port: int) -> list[Service]:
    index = _load_index()
    slugs = index["port_index"].get(str(port), [])
    return [_parse_service(s, index["services"][s]) for s in slugs if s in index["services"]]


def query_service(name: str) -> Optional[Service]:
    index = _load_index()
    name_lower = name.lower()

    # 1. Exact slug match
    if name_lower in index["services"]:
        return _parse_service(name_lower, index["services"][name_lower])

    # 2. Match against name, full_name, and aliases
    candidates = {}
    for slug, raw in index["services"].items():
        search_terms = [
            slug,
            raw.get("name", "").lower(),
            raw.get("full_name", "").lower(),
        ] + [a.lower() for a in raw.get("aliases", [])]
        candidates[slug] = search_terms

    # Exact match against any field
    for slug, terms in candidates.items():
        if name_lower in terms:
            return _parse_service(slug, index["services"][slug])

    # 3. Fuzzy match using difflib across all candidate terms
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
    return {
        "version": index.get("version"),
        "generated_at": index.get("generated_at"),
        "source_commit": index.get("source_commit"),
        "service_count": len(index.get("services", {})),
        "port_count": len(index.get("port_index", {})),
    }
