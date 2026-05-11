import sys

import click

from .display import (
    show_json, show_json_technique,
    show_list_plain, show_list_plain_techniques,
    show_list_rich, show_list_rich_techniques,
    show_plain, show_plain_technique,
    show_rich, show_rich_technique,
)
from .query import index_meta, list_all, list_all_techniques, query_port, query_service, query_technique


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("query", required=False)
@click.option("-c", "--category", metavar="CAT",
              help="Filter commands by category (enum, brute, exploit, post, lateral, tunnel).")
@click.option("--ad", "ad_only", is_flag=True, help="Search AD techniques only.")
@click.option("--platform", "-P", type=click.Choice(["linux", "windows", "both"]), default=None,
              help="Filter commands by platform (linux, windows, both).")
@click.option("--list", "show_list", is_flag=True, help="List all known entries.")
@click.option("--plain", is_flag=True, help="Plain text output (no color).")
@click.option("--json", "json_out", is_flag=True, help="JSON output for scripting.")
@click.option("--info", is_flag=True, help="Show index metadata (version, source commit).")
def main(query, category, ad_only, platform, show_list, plain, json_out, info):
    """
    HackTricks reference tool. Query by port, service name, or AD technique.

    \b
    Examples:
      hacktricks 445               # port lookup
      hacktricks smb               # service lookup
      hacktricks kerberoast        # AD technique lookup
      hacktricks kerberoast -P linux  # Linux commands only
      hacktricks smb -c enum       # filter by category
      hacktricks --list            # all known ports/services
      hacktricks --list --ad       # all AD techniques
    """
    if info:
        meta = index_meta()
        if json_out:
            import json
            print(json.dumps(meta, indent=2))
        else:
            for k, v in meta.items():
                print(f"{k}: {v}")
        return

    if show_list:
        if ad_only:
            techniques = list_all_techniques()
            if json_out:
                import json
                print(json.dumps([
                    {"slug": t.slug, "name": t.name, "phase": t.phase,
                     "required_access": t.required_access, "mitre": t.mitre}
                    for t in techniques
                ], indent=2))
            elif plain:
                show_list_plain_techniques(techniques)
            else:
                show_list_rich_techniques(techniques)
        else:
            services = list_all()
            if json_out:
                import json
                print(json.dumps([
                    {"slug": s.slug, "name": s.name, "full_name": s.full_name, "ports": s.ports}
                    for s in services
                ], indent=2))
            elif plain:
                show_list_plain(services)
            else:
                show_list_rich(services)
        return

    if not query:
        click.echo(click.get_current_context().get_help())
        return

    # AD-only mode: skip service lookup
    if ad_only:
        technique = query_technique(query)
        if technique is None:
            click.echo(f"No AD technique found matching '{query}'.", err=True)
            sys.exit(1)
        if json_out:
            show_json_technique(technique)
        elif plain:
            show_plain_technique(technique, category, platform)
        else:
            show_rich_technique(technique, category, platform)
        return

    # Port lookup → services only
    if query.isdigit():
        services = query_port(int(query))
        if not services:
            click.echo(f"No services found for port {query}.", err=True)
            sys.exit(1)
        if json_out:
            show_json(services)
        elif plain:
            show_plain(services, query, category, platform)
        else:
            show_rich(services, query, category, platform)
        return

    # Name lookup: exact technique match wins over fuzzy service match
    technique = query_technique(query)
    q = query.lower()
    svc = query_service(query)
    # Prefer technique when it's an exact hit (slug/name/alias) and service is only fuzzy
    if technique is not None and svc is not None:
        exact_svc = (svc.slug == q or svc.name.lower() == q or q in [a.lower() for a in svc.aliases])
        if not exact_svc:
            svc = None
    if svc is not None:
        if json_out:
            show_json([svc])
        elif plain:
            show_plain([svc], query, category, platform)
        else:
            show_rich([svc], query, category, platform)
        return

    technique = technique  # already resolved above
    if technique is not None:
        if json_out:
            show_json_technique(technique)
        elif plain:
            show_plain_technique(technique, category, platform)
        else:
            show_rich_technique(technique, category, platform)
        return

    click.echo(f"No service or technique found matching '{query}'.", err=True)
    sys.exit(1)
