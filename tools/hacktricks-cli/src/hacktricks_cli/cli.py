import sys

import click

from .display import show_json, show_list_plain, show_list_rich, show_plain, show_rich
from .query import index_meta, list_all, query_port, query_service


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("query", required=False)
@click.option("-c", "--category", metavar="CAT",
              help="Filter commands by category (enum, brute, exploit, post, lateral, tunnel).")
@click.option("--list", "show_list", is_flag=True, help="List all known ports and services.")
@click.option("--plain", is_flag=True, help="Plain text output (no color).")
@click.option("--json", "json_out", is_flag=True, help="JSON output for scripting.")
@click.option("--info", is_flag=True, help="Show index metadata (version, source commit).")
def main(query, category, show_list, plain, json_out, info):
    """
    HackTricks reference tool. Query by port number or service name.

    \b
    Examples:
      hacktricks 445          # port lookup
      hacktricks smb          # service lookup
      hacktricks smb -c enum  # filter by category
      hacktricks --list       # all known ports/services
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
        services = list_all()
        if plain or json_out:
            if json_out:
                import json
                print(json.dumps([
                    {"slug": s.slug, "name": s.name, "full_name": s.full_name, "ports": s.ports}
                    for s in services
                ], indent=2))
            else:
                show_list_plain(services)
        else:
            show_list_rich(services)
        return

    if not query:
        click.echo(click.get_current_context().get_help())
        return

    # Resolve services
    if query.isdigit():
        services = query_port(int(query))
        if not services:
            click.echo(f"No services found for port {query}.", err=True)
            sys.exit(1)
    else:
        svc = query_service(query)
        if svc is None:
            click.echo(f"No service found matching '{query}'.", err=True)
            sys.exit(1)
        services = [svc]

    if json_out:
        show_json(services)
    elif plain:
        show_plain(services, query, category)
    else:
        show_rich(services, query, category)
