import sys

import click

from .display import (
    show_json, show_json_technique,
    show_json_postex, show_json_postex_topic,
    show_json_privesc, show_json_privesc_platform,
    show_list_plain, show_list_plain_techniques, show_list_plain_postex, show_list_plain_privesc,
    show_list_rich, show_list_rich_techniques, show_list_rich_postex, show_list_rich_privesc,
    show_plain, show_plain_technique,
    show_plain_postex, show_plain_postex_topic,
    show_plain_privesc, show_plain_privesc_platform,
    show_rich, show_rich_technique,
    show_rich_postex, show_rich_postex_topic,
    show_rich_privesc, show_rich_privesc_platform,
)
from .query import (
    index_meta, list_all, list_all_techniques, list_all_postex, list_all_privesc,
    postex_index_counts, privesc_index_counts,
    query_port, query_service, query_technique,
    query_postex, query_postex_topic, _resolve_topic, POSTEX_TOPICS,
    query_privesc, query_privesc_platform, _resolve_privesc_platform, PRIVESC_PLATFORMS,
)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("query", nargs=-1, required=False)
@click.option("-c", "--category", metavar="CAT",
              help="Filter commands by category (enum, brute, exploit, post, lateral, tunnel).")
@click.option("--ad", "ad_only", is_flag=True, help="Search AD techniques only.")
@click.option("--postex", "postex_only", is_flag=True,
              help="Search post-exploitation techniques only (exfil, tunneling, brute-force, search-exploits).")
@click.option("--privesc", "privesc_only", is_flag=True,
              help="Search privilege escalation techniques only (linux, windows).")
@click.option("--platform", "-P", type=click.Choice(["linux", "windows", "both"]), default=None,
              help="Filter commands by platform (linux, windows, both).")
@click.option("--list", "show_list", is_flag=True, help="List all known entries.")
@click.option("--plain", is_flag=True, help="Plain text output (no color).")
@click.option("--json", "json_out", is_flag=True, help="JSON output for scripting.")
@click.option("--info", is_flag=True, help="Show index metadata (version, source commit).")
def main(query, category, ad_only, postex_only, privesc_only, platform, show_list, plain, json_out, info):
    """
    HackTricks reference tool. Query by port, service name, AD or post-exploitation technique.

    \b
    Examples:
      hacktricks 445               # port lookup
      hacktricks smb               # service lookup
      hacktricks kerberoast        # AD technique lookup
      hacktricks exfiltration      # all exfiltration techniques
      hacktricks chisel            # chisel tunneling commands
      hacktricks hydra             # hydra brute-force commands
      hacktricks kerberoast -P linux  # Linux commands only
      hacktricks smb -c enum       # filter by category
      hacktricks --list            # all known ports/services
      hacktricks --list --ad       # all AD techniques
      hacktricks --list --postex   # all post-exploitation techniques
      hacktricks privesc linux     # Linux privilege escalation checks
      hacktricks privesc windows   # Windows privilege escalation checks
      hacktricks suid              # SUID abuse technique
      hacktricks winpeas           # WinPEAS commands
    """
    query = " ".join(query) if query else None
    if info:
        meta = index_meta()
        meta["postex_topic_counts"] = postex_index_counts()
        meta["privesc_platform_counts"] = privesc_index_counts()
        if json_out:
            import json
            print(json.dumps(meta, indent=2))
        else:
            for k, v in meta.items():
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        print(f"  {kk}: {vv}")
                else:
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
        elif postex_only:
            techniques = list_all_postex()
            if json_out:
                import json
                print(json.dumps([
                    {"slug": t.slug, "name": t.name, "topic": t.topic,
                     "platform": t.platform, "cmd_count": len(t.commands)}
                    for t in techniques
                ], indent=2))
            elif plain:
                show_list_plain_postex(techniques)
            else:
                show_list_rich_postex(techniques)
        elif privesc_only:
            techniques = list_all_privesc()
            if json_out:
                import json
                print(json.dumps([
                    {"slug": t.slug, "name": t.name, "platform": t.platform,
                     "cmd_count": len(t.commands)}
                    for t in techniques
                ], indent=2))
            elif plain:
                show_list_plain_privesc(techniques)
            else:
                show_list_rich_privesc(techniques)
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

    # AD-only mode
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

    # Postex-only mode
    if postex_only:
        topic = _resolve_topic(query)
        if topic:
            techniques = query_postex_topic(topic)
            if not techniques:
                click.echo(f"No techniques found for topic '{topic}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_postex_topic(topic, techniques)
            elif plain:
                show_plain_postex_topic(topic, techniques, category, platform)
            else:
                show_rich_postex_topic(topic, techniques, category, platform)
        else:
            pt = query_postex(query)
            if pt is None:
                click.echo(f"No post-exploitation technique found matching '{query}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_postex(pt)
            elif plain:
                show_plain_postex(pt, category, platform)
            else:
                show_rich_postex(pt, category, platform)
        return

    # Privesc-only mode
    if privesc_only:
        plat = _resolve_privesc_platform(query)
        if plat:
            techniques = query_privesc_platform(plat)
            if not techniques:
                click.echo(f"No privesc techniques found for platform '{plat}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_privesc_platform(plat, techniques)
            elif plain:
                show_plain_privesc_platform(plat, techniques, category, platform)
            else:
                show_rich_privesc_platform(plat, techniques, category, platform)
        else:
            pt = query_privesc(query)
            if pt is None:
                click.echo(f"No privesc technique found matching '{query}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_privesc(pt)
            elif plain:
                show_plain_privesc(pt, category, platform)
            else:
                show_rich_privesc(pt, category, platform)
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

    q = query.lower()

    # Check for a postex topic match first (e.g. "exfiltration", "tunneling")
    topic = _resolve_topic(query)
    if topic:
        techniques = query_postex_topic(topic)
        if techniques:
            if json_out:
                show_json_postex_topic(topic, techniques)
            elif plain:
                show_plain_postex_topic(topic, techniques, category, platform)
            else:
                show_rich_postex_topic(topic, techniques, category, platform)
            return

    # Check for a privesc platform match (e.g. "linux", "windows", "privesc linux")
    plat = _resolve_privesc_platform(query)
    if plat:
        pv_techniques = query_privesc_platform(plat)
        if pv_techniques:
            if json_out:
                show_json_privesc_platform(plat, pv_techniques)
            elif plain:
                show_plain_privesc_platform(plat, pv_techniques, category, platform)
            else:
                show_rich_privesc_platform(plat, pv_techniques, category, platform)
            return

    # Resolve all four indexes; then pick the best match by exactness.
    technique = query_technique(query)
    svc = query_service(query)
    pt = query_postex(query)
    pv = query_privesc(query)

    def _is_exact_service(s):
        return s.slug == q or s.name.lower() == q or q in [a.lower() for a in s.aliases]

    def _is_exact_technique(t):
        return t.slug == q or t.name.lower() == q or q in [a.lower() for a in t.aliases]

    def _is_exact_postex(p):
        return p.slug == q or p.name.lower() == q or q in [a.lower() for a in p.aliases]

    def _is_exact_privesc(p):
        return p.slug == q or p.name.lower() == q or q in [a.lower() for a in p.aliases]

    exact_svc = svc is not None and _is_exact_service(svc)
    exact_ad = technique is not None and _is_exact_technique(technique)
    exact_pt = pt is not None and _is_exact_postex(pt)
    exact_pv = pv is not None and _is_exact_privesc(pv)

    # Priority: exact service > exact privesc > exact AD > exact postex >
    #           fuzzy service > fuzzy privesc > fuzzy postex > fuzzy AD
    if exact_svc:
        pass  # svc wins
    elif exact_pv:
        svc = None; technique = None; pt = None
    elif exact_ad and not exact_pt:
        svc = None; pt = None; pv = None
    elif exact_pt:
        svc = None; technique = None; pv = None
    elif svc is not None:
        technique = None; pt = None; pv = None  # fuzzy service
    elif pv is not None:
        technique = None; pt = None  # fuzzy privesc beats fuzzy postex/AD
    elif pt is not None:
        technique = None  # fuzzy postex beats fuzzy AD (tool names)
    # else technique (fuzzy AD) is last resort

    if svc is not None:
        if json_out:
            show_json([svc])
        elif plain:
            show_plain([svc], query, category, platform)
        else:
            show_rich([svc], query, category, platform)
        return

    if technique is not None:
        if json_out:
            show_json_technique(technique)
        elif plain:
            show_plain_technique(technique, category, platform)
        else:
            show_rich_technique(technique, category, platform)
        return

    if pv is not None:
        if json_out:
            show_json_privesc(pv)
        elif plain:
            show_plain_privesc(pv, category, platform)
        else:
            show_rich_privesc(pv, category, platform)
        return

    if pt is not None:
        if json_out:
            show_json_postex(pt)
        elif plain:
            show_plain_postex(pt, category, platform)
        else:
            show_rich_postex(pt, category, platform)
        return

    click.echo(f"No service or technique found matching '{query}'.", err=True)
    sys.exit(1)
