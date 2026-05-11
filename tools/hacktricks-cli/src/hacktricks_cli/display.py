import json
import textwrap
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.text import Text

from .query import PostexTechnique, PrivescTechnique, Service, Technique

CATEGORY_ORDER = [
    "enumeration",
    "brute-force",
    "exploitation",
    "post-exploitation",
    "lateral-movement",
    "tunneling",
    "persistence",
]

CATEGORY_COLORS = {
    "enumeration": "cyan",
    "brute-force": "yellow",
    "exploitation": "red",
    "post-exploitation": "magenta",
    "lateral-movement": "bright_magenta",
    "tunneling": "blue",
    "persistence": "dark_orange",
}

PHASE_COLORS = {
    "enumeration": "cyan",
    "credential-access": "yellow",
    "lateral-movement": "bright_magenta",
    "privilege-escalation": "red",
    "persistence": "dark_orange",
}

ACCESS_COLORS = {
    "none": "green",
    "domain-user": "cyan",
    "local-admin": "yellow",
    "domain-admin": "red",
    "specific-permission": "magenta",
}

PLATFORM_COLORS = {
    "linux": "green",
    "windows": "blue",
    "both": "dim",
}


def _category_label(cat: str) -> str:
    return cat.upper().replace("-", " ")


# ── Service: Rich output ───────────────────────────────────────────────────────

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
    platform_filter: Optional[str] = None,
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


# ── Service: Plain text output ─────────────────────────────────────────────────

def show_plain(
    services: list[Service],
    query: str,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
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


# ── Service: JSON output ───────────────────────────────────────────────────────

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


# ── Service: List output ───────────────────────────────────────────────────────

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


# ── Technique: Rich output ─────────────────────────────────────────────────────

def show_rich_technique(
    technique: Technique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    console = Console()

    phase_color = PHASE_COLORS.get(technique.phase, "white")
    access_color = ACCESS_COLORS.get(technique.required_access, "white")

    console.print(
        f"\n[bold bright_green]{technique.name}[/bold bright_green]"
        f"  [dim]({technique.full_name})[/dim]\n"
    )

    meta_parts = []
    if technique.phase:
        meta_parts.append(f"phase: [{phase_color}]{technique.phase}[/{phase_color}]")
    if technique.required_access:
        meta_parts.append(f"access: [{access_color}]{technique.required_access}[/{access_color}]")
    if technique.mitre:
        meta_parts.append(f"[dim]MITRE: {technique.mitre}[/dim]")
    if meta_parts:
        console.print("  " + "  |  ".join(meta_parts) + "\n")

    if technique.description:
        console.print(Panel(technique.description, border_style="dim", padding=(0, 1)))
        console.print()

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    if not commands:
        console.print("[dim]  No commands found.[/dim]\n")
        return

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
            plat_color = PLATFORM_COLORS.get(cmd.platform, "dim")
            plat_badge = f"[{plat_color}][{cmd.platform}][/{plat_color}]" if cmd.platform != "both" else ""
            label = f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]"
            if plat_badge:
                label += f"  {plat_badge}"
            console.print(label)
            console.print(
                Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                no_wrap=False,
            )
            if cmd.note:
                console.print(f"  [dim]↳ {cmd.note}[/dim]")
            console.print()
            idx += 1

    if technique.see_also:
        slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in technique.see_also)
        console.print(f"[dim]SEE ALSO:[/dim]  {slugs}\n")


# ── Technique: Plain text output ───────────────────────────────────────────────

def show_plain_technique(
    technique: Technique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    lines = []
    lines.append(f"{technique.name} ({technique.full_name})")
    meta = []
    if technique.phase:
        meta.append(f"phase: {technique.phase}")
    if technique.required_access:
        meta.append(f"access: {technique.required_access}")
    if technique.mitre:
        meta.append(f"MITRE: {technique.mitre}")
    if meta:
        lines.append("  " + "  |  ".join(meta))
    lines.append("")

    if technique.description:
        lines.append(technique.description)
        lines.append("")

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    by_cat: dict[str, list] = {}
    for cmd in commands:
        by_cat.setdefault(cmd.category, []).append(cmd)

    idx = 1
    ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
    ordered_cats += [c for c in by_cat if c not in CATEGORY_ORDER]

    for cat in ordered_cats:
        lines.append(f"--- {_category_label(cat)} ---")
        for cmd in by_cat[cat]:
            plat = f" [{cmd.platform}]" if cmd.platform != "both" else ""
            lines.append(f"[{idx}] {cmd.name}{plat}")
            for line in cmd.command.splitlines():
                lines.append(f"    {line}")
            if cmd.note:
                lines.append(f"    -> {cmd.note}")
            lines.append("")
            idx += 1

    if technique.see_also:
        lines.append(f"SEE ALSO: {' | '.join(technique.see_also)}")
        lines.append("")

    print("\n".join(lines))


# ── Technique: JSON output ─────────────────────────────────────────────────────

def show_json_technique(technique: Technique):
    out = {
        "slug": technique.slug,
        "name": technique.name,
        "full_name": technique.full_name,
        "description": technique.description,
        "phase": technique.phase,
        "mitre": technique.mitre,
        "required_access": technique.required_access,
        "commands": [
            {
                "name": c.name,
                "platform": c.platform,
                "category": c.category,
                "command": c.command,
                "note": c.note,
            }
            for c in technique.commands
        ],
        "aliases": technique.aliases,
        "see_also": technique.see_also,
    }
    print(json.dumps(out, indent=2))


# ── Technique: List output ─────────────────────────────────────────────────────

def show_list_rich_techniques(techniques: list[Technique]):
    from rich.table import Table
    console = Console()
    table = Table(title="AD Attack Techniques", show_header=True, header_style="bold bright_green")
    table.add_column("Slug", style="bold")
    table.add_column("Name")
    table.add_column("Phase", style="cyan")
    table.add_column("Access", style="yellow")
    table.add_column("MITRE", style="dim")
    table.add_column("Cmds", justify="right", style="dim")

    for t in techniques:
        table.add_row(t.slug, t.full_name, t.phase, t.required_access, t.mitre, str(len(t.commands)))

    console.print(table)


def show_list_plain_techniques(techniques: list[Technique]):
    for t in techniques:
        mitre = f"  {t.mitre}" if t.mitre else ""
        print(f"{t.slug:<35} {t.phase:<22} {t.required_access:<20}{mitre}")


TOPIC_COLORS = {
    "exfiltration": "magenta",
    "tunneling": "blue",
    "brute-force": "yellow",
    "search-exploits": "cyan",
}

PRIVESC_PLATFORM_COLORS = {
    "linux": "green",
    "windows": "blue",
    "both": "dim",
}


# ── PostexTechnique: Rich output ───────────────────────────────────────────────

def show_rich_postex(
    technique: PostexTechnique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    console = Console()
    topic_color = TOPIC_COLORS.get(technique.topic, "white")

    console.print(
        f"\n[bold bright_green]{technique.name}[/bold bright_green]"
        f"  [dim]({technique.full_name})[/dim]\n"
    )
    console.print(
        f"  topic: [{topic_color}]{technique.topic}[/{topic_color}]"
        f"  |  platform: [{PLATFORM_COLORS.get(technique.platform, 'dim')}]{technique.platform}[/{PLATFORM_COLORS.get(technique.platform, 'dim')}]\n"
    )

    if technique.description:
        console.print(Panel(technique.description, border_style="dim", padding=(0, 1)))
        console.print()

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    if not commands:
        console.print("[dim]  No commands found.[/dim]\n")
        return

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
            plat_color = PLATFORM_COLORS.get(cmd.platform, "dim")
            plat_badge = f"[{plat_color}][{cmd.platform}][/{plat_color}]" if cmd.platform != "both" else ""
            label = f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]"
            if plat_badge:
                label += f"  {plat_badge}"
            console.print(label)
            console.print(
                Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                no_wrap=False,
            )
            if cmd.note:
                console.print(f"  [dim]↳ {cmd.note}[/dim]")
            console.print()
            idx += 1

    if technique.see_also:
        slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in technique.see_also)
        console.print(f"[dim]SEE ALSO:[/dim]  {slugs}\n")


def show_rich_postex_topic(
    topic: str,
    techniques: list[PostexTechnique],
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    console = Console()
    topic_color = TOPIC_COLORS.get(topic, "white")
    console.print(f"\n[bold {topic_color}]{topic.upper()}[/bold {topic_color}]  [dim]({len(techniques)} techniques)[/dim]\n")

    for tech in techniques:
        console.print(Rule(f"[bold]{tech.name}[/bold]  [dim]({tech.slug})[/dim]", style=topic_color))

        if tech.description:
            console.print(f"  [dim]{tech.description}[/dim]")
            console.print()

        commands = tech.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]
        if platform_filter and platform_filter != "both":
            commands = [c for c in commands if c.platform in (platform_filter, "both")]

        if not commands:
            console.print("[dim]  No commands.[/dim]\n")
            continue

        idx = 1
        for cmd in commands:
            plat_color = PLATFORM_COLORS.get(cmd.platform, "dim")
            plat_badge = f"[{plat_color}][{cmd.platform}][/{plat_color}]" if cmd.platform != "both" else ""
            label = f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]"
            if plat_badge:
                label += f"  {plat_badge}"
            console.print(label)
            console.print(
                Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                no_wrap=False,
            )
            if cmd.note:
                console.print(f"  [dim]↳ {cmd.note}[/dim]")
            console.print()
            idx += 1

        if tech.see_also:
            slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in tech.see_also)
            console.print(f"  [dim]SEE ALSO:[/dim]  {slugs}\n")


# ── PostexTechnique: Plain text output ─────────────────────────────────────────

def show_plain_postex(
    technique: PostexTechnique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    lines = [
        f"{technique.name} ({technique.full_name})",
        f"  topic: {technique.topic}  |  platform: {technique.platform}",
        "",
    ]

    if technique.description:
        lines.append(technique.description)
        lines.append("")

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    by_cat: dict[str, list] = {}
    for cmd in commands:
        by_cat.setdefault(cmd.category, []).append(cmd)

    idx = 1
    ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
    ordered_cats += [c for c in by_cat if c not in CATEGORY_ORDER]

    for cat in ordered_cats:
        lines.append(f"--- {_category_label(cat)} ---")
        for cmd in by_cat[cat]:
            plat = f" [{cmd.platform}]" if cmd.platform != "both" else ""
            lines.append(f"[{idx}] {cmd.name}{plat}")
            for line in cmd.command.splitlines():
                lines.append(f"    {line}")
            if cmd.note:
                lines.append(f"    -> {cmd.note}")
            lines.append("")
            idx += 1

    if technique.see_also:
        lines.append(f"SEE ALSO: {' | '.join(technique.see_also)}")
        lines.append("")

    print("\n".join(lines))


def show_plain_postex_topic(
    topic: str,
    techniques: list[PostexTechnique],
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    print(f"{topic.upper()} ({len(techniques)} techniques)\n")
    for tech in techniques:
        print(f"=== {tech.name} ({tech.slug}) ===")
        if tech.description:
            print(tech.description)
            print()

        commands = tech.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]
        if platform_filter and platform_filter != "both":
            commands = [c for c in commands if c.platform in (platform_filter, "both")]

        idx = 1
        for cmd in commands:
            plat = f" [{cmd.platform}]" if cmd.platform != "both" else ""
            print(f"[{idx}] {cmd.name}{plat}")
            for line in cmd.command.splitlines():
                print(f"    {line}")
            if cmd.note:
                print(f"    -> {cmd.note}")
            print()
            idx += 1

        if tech.see_also:
            print(f"SEE ALSO: {' | '.join(tech.see_also)}\n")


# ── PostexTechnique: JSON output ───────────────────────────────────────────────

def show_json_postex(technique: PostexTechnique):
    out = {
        "slug": technique.slug,
        "name": technique.name,
        "full_name": technique.full_name,
        "description": technique.description,
        "topic": technique.topic,
        "platform": technique.platform,
        "commands": [
            {
                "name": c.name,
                "platform": c.platform,
                "category": c.category,
                "command": c.command,
                "note": c.note,
            }
            for c in technique.commands
        ],
        "aliases": technique.aliases,
        "see_also": technique.see_also,
    }
    print(json.dumps(out, indent=2))


def show_json_postex_topic(topic: str, techniques: list[PostexTechnique]):
    out = {
        "topic": topic,
        "techniques": [
            {
                "slug": t.slug,
                "name": t.name,
                "full_name": t.full_name,
                "description": t.description,
                "platform": t.platform,
                "commands": [
                    {"name": c.name, "platform": c.platform, "category": c.category,
                     "command": c.command, "note": c.note}
                    for c in t.commands
                ],
                "aliases": t.aliases,
                "see_also": t.see_also,
            }
            for t in techniques
        ],
    }
    print(json.dumps(out, indent=2))


# ── PostexTechnique: List output ───────────────────────────────────────────────

def show_list_rich_postex(techniques: list[PostexTechnique]):
    from rich.table import Table
    console = Console()
    table = Table(title="Post-Exploitation Techniques", show_header=True, header_style="bold bright_green")
    table.add_column("Slug", style="bold")
    table.add_column("Name")
    table.add_column("Topic", style="cyan")
    table.add_column("Platform", style="dim")
    table.add_column("Cmds", justify="right", style="dim")

    for t in techniques:
        topic_color = TOPIC_COLORS.get(t.topic, "white")
        table.add_row(t.slug, t.name, f"[{topic_color}]{t.topic}[/{topic_color}]", t.platform, str(len(t.commands)))

    console.print(table)


def show_list_plain_postex(techniques: list[PostexTechnique]):
    for t in techniques:
        print(f"{t.slug:<40} {t.topic:<18} {t.platform:<8} {t.name}")


# ── PrivescTechnique: Rich output ──────────────────────────────────────────────

def show_rich_privesc(
    technique: PrivescTechnique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    console = Console()
    plat_color = PRIVESC_PLATFORM_COLORS.get(technique.platform, "white")

    console.print(
        f"\n[bold bright_green]{technique.name}[/bold bright_green]"
        f"  [dim]({technique.full_name})[/dim]\n"
    )
    console.print(
        f"  platform: [{plat_color}]{technique.platform}[/{plat_color}]  |  "
        f"[dim]privesc[/dim]\n"
    )

    if technique.description:
        console.print(Panel(technique.description, border_style="dim", padding=(0, 1)))
        console.print()

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    if not commands:
        console.print("[dim]  No commands found.[/dim]\n")
        return

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
            plat_color2 = PLATFORM_COLORS.get(cmd.platform, "dim")
            plat_badge = f"[{plat_color2}][{cmd.platform}][/{plat_color2}]" if cmd.platform != "both" else ""
            label = f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]"
            if plat_badge:
                label += f"  {plat_badge}"
            console.print(label)
            console.print(
                Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                no_wrap=False,
            )
            if cmd.note:
                console.print(f"  [dim]↳ {cmd.note}[/dim]")
            console.print()
            idx += 1

    if technique.see_also:
        slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in technique.see_also)
        console.print(f"[dim]SEE ALSO:[/dim]  {slugs}\n")


def show_rich_privesc_platform(
    platform: str,
    techniques: list[PrivescTechnique],
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    console = Console()
    plat_color = PRIVESC_PLATFORM_COLORS.get(platform, "white")
    console.print(
        f"\n[bold {plat_color}]{platform.upper()} PRIVESC[/bold {plat_color}]"
        f"  [dim]({len(techniques)} techniques)[/dim]\n"
    )

    for tech in techniques:
        console.print(Rule(f"[bold]{tech.name}[/bold]  [dim]({tech.slug})[/dim]", style=plat_color))

        if tech.description:
            console.print(f"  [dim]{tech.description}[/dim]")
            console.print()

        commands = tech.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]
        if platform_filter and platform_filter != "both":
            commands = [c for c in commands if c.platform in (platform_filter, "both")]

        if not commands:
            console.print("[dim]  No commands.[/dim]\n")
            continue

        idx = 1
        for cmd in commands:
            plat_color2 = PLATFORM_COLORS.get(cmd.platform, "dim")
            plat_badge = f"[{plat_color2}][{cmd.platform}][/{plat_color2}]" if cmd.platform != "both" else ""
            label = f"  [bold white]\\[{idx}][/bold white] [italic]{cmd.name}[/italic]"
            if plat_badge:
                label += f"  {plat_badge}"
            console.print(label)
            console.print(
                Syntax(cmd.command, "bash", theme="monokai", word_wrap=True, indent_guides=False),
                no_wrap=False,
            )
            if cmd.note:
                console.print(f"  [dim]↳ {cmd.note}[/dim]")
            console.print()
            idx += 1

        if tech.see_also:
            slugs = "  ·  ".join(f"[cyan]{s}[/cyan]" for s in tech.see_also)
            console.print(f"  [dim]SEE ALSO:[/dim]  {slugs}\n")


# ── PrivescTechnique: Plain text output ────────────────────────────────────────

def show_plain_privesc(
    technique: PrivescTechnique,
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    lines = [
        f"{technique.name} ({technique.full_name})",
        f"  platform: {technique.platform}  |  privesc",
        "",
    ]

    if technique.description:
        lines.append(technique.description)
        lines.append("")

    commands = technique.commands
    if category_filter:
        norm = category_filter.lower()
        commands = [c for c in commands if norm in c.category]
    if platform_filter and platform_filter != "both":
        commands = [c for c in commands if c.platform in (platform_filter, "both")]

    by_cat: dict[str, list] = {}
    for cmd in commands:
        by_cat.setdefault(cmd.category, []).append(cmd)

    idx = 1
    ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
    ordered_cats += [c for c in by_cat if c not in CATEGORY_ORDER]

    for cat in ordered_cats:
        lines.append(f"--- {_category_label(cat)} ---")
        for cmd in by_cat[cat]:
            plat = f" [{cmd.platform}]" if cmd.platform != "both" else ""
            lines.append(f"[{idx}] {cmd.name}{plat}")
            for line in cmd.command.splitlines():
                lines.append(f"    {line}")
            if cmd.note:
                lines.append(f"    -> {cmd.note}")
            lines.append("")
            idx += 1

    if technique.see_also:
        lines.append(f"SEE ALSO: {' | '.join(technique.see_also)}")
        lines.append("")

    print("\n".join(lines))


def show_plain_privesc_platform(
    platform: str,
    techniques: list[PrivescTechnique],
    category_filter: Optional[str] = None,
    platform_filter: Optional[str] = None,
):
    print(f"{platform.upper()} PRIVESC ({len(techniques)} techniques)\n")
    for tech in techniques:
        print(f"=== {tech.name} ({tech.slug}) ===")
        if tech.description:
            print(tech.description)
            print()

        commands = tech.commands
        if category_filter:
            norm = category_filter.lower()
            commands = [c for c in commands if norm in c.category]
        if platform_filter and platform_filter != "both":
            commands = [c for c in commands if c.platform in (platform_filter, "both")]

        idx = 1
        for cmd in commands:
            plat = f" [{cmd.platform}]" if cmd.platform != "both" else ""
            print(f"[{idx}] {cmd.name}{plat}")
            for line in cmd.command.splitlines():
                print(f"    {line}")
            if cmd.note:
                print(f"    -> {cmd.note}")
            print()
            idx += 1

        if tech.see_also:
            print(f"SEE ALSO: {' | '.join(tech.see_also)}\n")


# ── PrivescTechnique: JSON output ──────────────────────────────────────────────

def show_json_privesc(technique: PrivescTechnique):
    out = {
        "slug": technique.slug,
        "name": technique.name,
        "full_name": technique.full_name,
        "description": technique.description,
        "platform": technique.platform,
        "commands": [
            {
                "name": c.name,
                "platform": c.platform,
                "category": c.category,
                "command": c.command,
                "note": c.note,
            }
            for c in technique.commands
        ],
        "aliases": technique.aliases,
        "see_also": technique.see_also,
    }
    print(json.dumps(out, indent=2))


def show_json_privesc_platform(platform: str, techniques: list[PrivescTechnique]):
    out = {
        "platform": platform,
        "techniques": [
            {
                "slug": t.slug,
                "name": t.name,
                "full_name": t.full_name,
                "description": t.description,
                "platform": t.platform,
                "commands": [
                    {"name": c.name, "platform": c.platform, "category": c.category,
                     "command": c.command, "note": c.note}
                    for c in t.commands
                ],
                "aliases": t.aliases,
                "see_also": t.see_also,
            }
            for t in techniques
        ],
    }
    print(json.dumps(out, indent=2))


# ── PrivescTechnique: List output ──────────────────────────────────────────────

def show_list_rich_privesc(techniques: list[PrivescTechnique]):
    from rich.table import Table
    console = Console()
    table = Table(title="Privilege Escalation Techniques", show_header=True, header_style="bold bright_green")
    table.add_column("Slug", style="bold")
    table.add_column("Name")
    table.add_column("Platform", style="cyan")
    table.add_column("Cmds", justify="right", style="dim")

    for t in techniques:
        plat_color = PRIVESC_PLATFORM_COLORS.get(t.platform, "white")
        table.add_row(t.slug, t.name, f"[{plat_color}]{t.platform}[/{plat_color}]", str(len(t.commands)))

    console.print(table)


def show_list_plain_privesc(techniques: list[PrivescTechnique]):
    for t in techniques:
        print(f"{t.slug:<35} {t.platform:<10} {t.name}")
