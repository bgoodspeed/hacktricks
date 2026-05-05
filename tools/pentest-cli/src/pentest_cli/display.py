import json
import textwrap
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.text import Text

from .query import Service

CATEGORY_ORDER = [
    "enumeration",
    "brute-force",
    "exploitation",
    "post-exploitation",
    "lateral-movement",
    "tunneling",
]

CATEGORY_COLORS = {
    "enumeration": "cyan",
    "brute-force": "yellow",
    "exploitation": "red",
    "post-exploitation": "magenta",
    "lateral-movement": "bright_magenta",
    "tunneling": "blue",
}


def _category_label(cat: str) -> str:
    return cat.upper().replace("-", " ")


# ── Rich output ────────────────────────────────────────────────────────────────

def _rich_header(console: Console, services: list[Service], query: str):
    if query.isdigit():
        port_str = f"PORT {query}"
        if services:
            names = "  ·  ".join(
                f"[bold]{s.name}[/bold] ([dim]{s.full_name}[/dim])" for s in services
            )
            console.print(f"\n[bold bright_green]{port_str}[/bold bright_green]  →  {names}\n")
        else:
            console.print(f"\n[bold bright_green]{port_str}[/bold bright_green]  [red]→  No services found[/red]\n")
    else:
        s = services[0] if services else None
        if s:
            ports_str = ", ".join(str(p) for p in s.ports)
            console.print(
                f"\n[bold bright_green]{s.name}[/bold bright_green]"
                f"  [dim]({s.full_name})[/dim]"
                f"  [dim]ports: {ports_str}[/dim]\n"
            )


def show_rich(
    services: list[Service],
    query: str,
    category_filter: Optional[str] = None,
):
    console = Console()
    _rich_header(console, services, query)

    for svc in services:
        if len(services) > 1:
            console.print(Rule(f"[bold]{svc.name}[/bold]  ({svc.full_name})", style="bright_green"))

        if svc.description:
            console.print(Panel(svc.description, border_style="dim", padding=(0, 1)))
            console.print()

        commands = svc.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]

        if not commands:
            console.print("[dim]  No commands found.[/dim]\n")
            continue

        # Group by category in canonical order
        by_cat: dict[str, list] = {}
        for cmd in commands:
            by_cat.setdefault(cmd.category, []).append(cmd)

        idx = 1
        ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
        ordered_cats += [c for c in by_cat if c not in CATEGORY_ORDER]

        for cat in ordered_cats:
            color = CATEGORY_COLORS.get(cat, "white")
            console.print(Rule(f"[{color}]{_category_label(cat)}[/{color}]", style=f"dim {color}"))
            for cmd in by_cat[cat]:
                console.print(f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]")
                console.print(
                    Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                    no_wrap=False,
                )
                if cmd.note:
                    console.print(f"  [dim]↳ {cmd.note}[/dim]")
                console.print()
                idx += 1

        if svc.see_also:
            slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in svc.see_also)
            console.print(f"[dim]SEE ALSO:[/dim]  {slugs}\n")


# ── Plain text output ──────────────────────────────────────────────────────────

def show_plain(
    services: list[Service],
    query: str,
    category_filter: Optional[str] = None,
):
    lines = []

    if query.isdigit() and services:
        names = " | ".join(f"{s.name} ({s.full_name})" for s in services)
        lines.append(f"PORT {query} -> {names}")
    elif services:
        s = services[0]
        lines.append(f"{s.name} ({s.full_name})  ports: {', '.join(str(p) for p in s.ports)}")
    else:
        lines.append(f"No results for: {query}")

    lines.append("")

    for svc in services:
        if len(services) > 1:
            lines.append(f"=== {svc.name} ({svc.full_name}) ===")

        if svc.description:
            lines.append(svc.description)
            lines.append("")

        commands = svc.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]

        by_cat: dict[str, list] = {}
        for cmd in commands:
            by_cat.setdefault(cmd.category, []).append(cmd)

        idx = 1
        ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
        ordered_cats += [c for c in by_cat if c not in CATEGORY_ORDER]

        for cat in ordered_cats:
            lines.append(f"--- {_category_label(cat)} ---")
            for cmd in by_cat[cat]:
                lines.append(f"[{idx}] {cmd.name}")
                for line in cmd.command.splitlines():
                    lines.append(f"    {line}")
                if cmd.note:
                    lines.append(f"    -> {cmd.note}")
                lines.append("")
                idx += 1

        if svc.see_also:
            lines.append(f"SEE ALSO: {' | '.join(svc.see_also)}")
            lines.append("")

    print("\n".join(lines))


# ── JSON output ────────────────────────────────────────────────────────────────

def show_json(services: list[Service]):
    out = []
    for svc in services:
        out.append({
            "slug": svc.slug,
            "name": svc.name,
            "full_name": svc.full_name,
            "ports": svc.ports,
            "description": svc.description,
            "commands": [
                {"name": c.name, "category": c.category, "command": c.command, "note": c.note}
                for c in svc.commands
            ],
            "aliases": svc.aliases,
            "see_also": svc.see_also,
        })
    print(json.dumps(out if len(out) > 1 else out[0] if out else {}, indent=2))


# ── List output ────────────────────────────────────────────────────────────────

def show_list_rich(services: list[Service]):
    from rich.table import Table
    console = Console()
    table = Table(title="Known Ports & Services", show_header=True, header_style="bold bright_green")
    table.add_column("Port(s)", style="cyan", no_wrap=True)
    table.add_column("Slug", style="bold")
    table.add_column("Name")
    table.add_column("Commands", justify="right", style="dim")

    for svc in services:
        ports_str = ", ".join(str(p) for p in svc.ports)
        table.add_row(ports_str, svc.slug, svc.full_name, str(len(svc.commands)))

    console.print(table)


def show_list_plain(services: list[Service]):
    for svc in services:
        ports_str = ", ".join(str(p) for p in svc.ports)
        print(f"{ports_str:<20} {svc.slug:<25} {svc.full_name}")
