import sys

import click

from .display import (
    show_json, show_json_technique,
    show_json_postex, show_json_postex_topic,
    show_json_privesc, show_json_privesc_platform,
    show_json_web, show_json_web_type,
    show_json_gtfobin, show_json_gtfo_func,
    show_list_plain, show_list_plain_techniques, show_list_plain_postex, show_list_plain_privesc,
    show_list_plain_web, show_list_plain_gtfo,
    show_list_rich, show_list_rich_techniques, show_list_rich_postex, show_list_rich_privesc,
    show_list_rich_web, show_list_rich_gtfo,
    show_plain, show_plain_technique,
    show_plain_postex, show_plain_postex_topic,
    show_plain_privesc, show_plain_privesc_platform,
    show_plain_web, show_plain_web_type,
    show_plain_gtfobin, show_plain_gtfo_func,
    show_rich, show_rich_technique,
    show_rich_postex, show_rich_postex_topic,
    show_rich_privesc, show_rich_privesc_platform,
    show_rich_web, show_rich_web_type,
    show_rich_gtfobin, show_rich_gtfo_func,
)
from .query import (
    index_meta, list_all, list_all_techniques, list_all_postex, list_all_privesc, list_all_web,
    list_all_gtfo,
    postex_index_counts, privesc_index_counts, web_index_counts, gtfobins_index_counts,
    query_port, query_service, query_technique,
    query_postex, query_postex_topic, _resolve_topic, POSTEX_TOPICS,
    query_privesc, query_privesc_platform, _resolve_privesc_platform, PRIVESC_PLATFORMS,
    query_web, query_web_type, _resolve_web_type, WEB_VULN_TYPES,
    query_gtfobin, query_gtfo_func, query_gtfo_ctx,
    _resolve_gtfo_func, _resolve_gtfo_ctx, GTFO_FUNCTION_TYPES, GTFO_CONTEXT_TYPES,
    suggest,
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
@click.option("--web", "web_only", is_flag=True,
              help="Search web vulnerability techniques only (sqli, xss, ssrf, ssti, etc.).")
@click.option("--gtfo", "gtfo_only", is_flag=True,
              help="Search GTFOBins (binaries for living-off-the-land / privilege escalation).")
@click.option("--func", "gtfo_func", metavar="TYPE", default=None,
              help=f"Filter GTFOBins by function type ({', '.join(GTFO_FUNCTION_TYPES)}).")
@click.option("--ctx", "gtfo_ctx", metavar="CTX", default=None,
              help=f"Filter GTFOBins by context ({', '.join(GTFO_CONTEXT_TYPES)}).")
@click.option("--platform", "-P", type=click.Choice(["linux", "windows", "both"]), default=None,
              help="Filter commands by platform (linux, windows, both).")
@click.option("--list", "show_list", is_flag=True, help="List all known entries.")
@click.option("--plain", is_flag=True, help="Plain text output (no color).")
@click.option("--json", "json_out", is_flag=True, help="JSON output for scripting.")
@click.option("--info", is_flag=True, help="Show index metadata (version, source commit).")
def main(query, category, ad_only, postex_only, privesc_only, web_only, gtfo_only, gtfo_func, gtfo_ctx, platform, show_list, plain, json_out, info):
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
      hacktricks sqli              # SQL injection payloads & commands
      hacktricks xss               # XSS payload cheatsheet
      hacktricks --web injection   # all injection-type web vulns
      hacktricks --list --web      # all web vulnerability techniques
      hacktricks --gtfo curl       # GTFOBins entry for curl
      hacktricks --gtfo python     # GTFOBins entry for python
      hacktricks --gtfo shell      # all binaries with shell escape
      hacktricks --gtfo --func file-read          # all binaries with file-read
      hacktricks --gtfo --func shell --ctx suid   # shell via SUID
      hacktricks --list --gtfo     # list all GTFOBins binaries
    """
    query = " ".join(query) if query else None
    if info:
        meta = index_meta()
        meta["postex_topic_counts"] = postex_index_counts()
        meta["privesc_platform_counts"] = privesc_index_counts()
        meta["web_type_counts"] = web_index_counts()
        meta["gtfobins_counts"] = gtfobins_index_counts()
        if json_out:
            import json
            print(json.dumps(meta, indent=2))
        else:
            for k, v in meta.items():
                if isinstance(v, dict):
                    for kk, vv in v.items():
                        if isinstance(vv, dict):
                            print(f"  {kk}:")
                            for kkk, vvv in vv.items():
                                print(f"    {kkk}: {vvv}")
                        else:
                            print(f"  {kk}: {vv}")
                else:
                    print(f"{k}: {v}")
        return

    if show_list:
        if gtfo_only:
            binaries = list_all_gtfo()
            if json_out:
                import json
                print(json.dumps([
                    {"name": b.name, "functions": list(b.functions.keys()),
                     "contexts": sorted({ctx for entries in b.functions.values()
                                         for e in entries for ctx in e.contexts})}
                    for b in binaries
                ], indent=2))
            elif plain:
                show_list_plain_gtfo(binaries)
            else:
                show_list_rich_gtfo(binaries)
            return
        if web_only:
            techniques = list_all_web()
            if json_out:
                import json
                print(json.dumps([
                    {"slug": t.slug, "name": t.name, "vuln_type": t.vuln_type,
                     "payload_count": len(t.payloads), "cmd_count": len(t.commands)}
                    for t in techniques
                ], indent=2))
            elif plain:
                show_list_plain_web(techniques)
            else:
                show_list_rich_web(techniques)
            return
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

    if not query and not gtfo_only:
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

    # Web-only mode
    if web_only:
        vtype = _resolve_web_type(query)
        if vtype:
            techniques = query_web_type(vtype)
            if not techniques:
                click.echo(f"No web techniques found for type '{vtype}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_web_type(vtype, techniques)
            elif plain:
                show_plain_web_type(vtype, techniques, category, platform)
            else:
                show_rich_web_type(vtype, techniques, category, platform)
        else:
            wt = query_web(query)
            if wt is None:
                click.echo(f"No web vulnerability found matching '{query}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_web(wt)
            elif plain:
                show_plain_web(wt, category, platform)
            else:
                show_rich_web(wt, category, platform)
        return

    # GTFOBins-only mode
    if gtfo_only:
        resolved_func = _resolve_gtfo_func(gtfo_func) if gtfo_func else None
        resolved_ctx = _resolve_gtfo_ctx(gtfo_ctx) if gtfo_ctx else None

        # --func without a query: list all binaries with that function type
        if resolved_func and not query:
            binaries = query_gtfo_func(resolved_func)
            if not binaries:
                click.echo(f"No GTFOBins entries found for function type '{resolved_func}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_gtfo_func(resolved_func, binaries)
            elif plain:
                show_plain_gtfo_func(resolved_func, binaries, resolved_ctx)
            else:
                show_rich_gtfo_func(resolved_func, binaries, resolved_ctx)
            return

        # query might be a function type (e.g. "hacktricks --gtfo shell")
        func_from_query = _resolve_gtfo_func(query) if query else None
        if func_from_query and not resolved_func:
            binaries = query_gtfo_func(func_from_query)
            if not binaries:
                click.echo(f"No GTFOBins entries found for function type '{func_from_query}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_gtfo_func(func_from_query, binaries)
            elif plain:
                show_plain_gtfo_func(func_from_query, binaries, resolved_ctx)
            else:
                show_rich_gtfo_func(func_from_query, binaries, resolved_ctx)
            return

        # query might be a context (e.g. "hacktricks --gtfo suid")
        ctx_from_query = _resolve_gtfo_ctx(query) if query else None
        if ctx_from_query and not resolved_ctx and not resolved_func:
            binaries = query_gtfo_ctx(ctx_from_query)
            if not binaries:
                click.echo(f"No GTFOBins entries found for context '{ctx_from_query}'.", err=True)
                sys.exit(1)
            if json_out:
                show_json_gtfo_func(f"[ctx:{ctx_from_query}]", binaries)
            elif plain:
                show_list_plain_gtfo(binaries)
            else:
                show_list_rich_gtfo(binaries)
            return

        # Lookup a specific binary
        if not query:
            click.echo(click.get_current_context().get_help())
            return

        binary = query_gtfobin(query)
        if binary is None:
            click.echo(f"No GTFOBins entry found for '{query}'.", err=True)
            sys.exit(1)
        if json_out:
            show_json_gtfobin(binary)
        elif plain:
            show_plain_gtfobin(binary, resolved_func, resolved_ctx)
        else:
            show_rich_gtfobin(binary, resolved_func, resolved_ctx)
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

    # Resolve all indexes; then pick the best match by exactness.
    technique = query_technique(query)
    svc = query_service(query)
    pt = query_postex(query)
    pv = query_privesc(query)
    wt = query_web(query)
    gtfo = query_gtfobin(query)

    def _is_exact_service(s):
        return s.slug == q or s.name.lower() == q or q in [a.lower() for a in s.aliases]

    def _is_exact_technique(t):
        return t.slug == q or t.name.lower() == q or q in [a.lower() for a in t.aliases]

    def _is_exact_postex(p):
        return p.slug == q or p.name.lower() == q or q in [a.lower() for a in p.aliases]

    def _is_exact_privesc(p):
        return p.slug == q or p.name.lower() == q or q in [a.lower() for a in p.aliases]

    def _is_exact_web(w):
        return w.slug == q or w.name.lower() == q or q in [a.lower() for a in w.aliases]

    exact_svc = svc is not None and _is_exact_service(svc)
    exact_ad = technique is not None and _is_exact_technique(technique)
    exact_pt = pt is not None and _is_exact_postex(pt)
    exact_pv = pv is not None and _is_exact_privesc(pv)
    exact_wt = wt is not None and _is_exact_web(wt)
    exact_gtfo = gtfo is not None and gtfo.name == q

    # Priority: exact service > exact privesc > exact AD > exact web > exact postex >
    #           exact gtfo > fuzzy service > fuzzy privesc > fuzzy web > fuzzy postex >
    #           fuzzy gtfo > fuzzy AD
    if exact_svc:
        pass  # svc wins
    elif exact_pv:
        svc = None; technique = None; pt = None; wt = None; gtfo = None
    elif exact_ad and not exact_pt and not exact_wt:
        svc = None; pt = None; pv = None; wt = None; gtfo = None
    elif exact_wt:
        svc = None; technique = None; pt = None; pv = None; gtfo = None
    elif exact_pt:
        svc = None; technique = None; pv = None; wt = None; gtfo = None
    elif exact_gtfo:
        svc = None; technique = None; pt = None; pv = None; wt = None
    elif svc is not None:
        technique = None; pt = None; pv = None; wt = None; gtfo = None  # fuzzy service
    elif pv is not None:
        technique = None; pt = None; wt = None; gtfo = None  # fuzzy privesc
    elif wt is not None:
        technique = None; pt = None; gtfo = None  # fuzzy web beats fuzzy postex/AD/gtfo
    elif pt is not None:
        technique = None; gtfo = None  # fuzzy postex beats fuzzy AD/gtfo (tool names)
    elif gtfo is not None:
        technique = None  # fuzzy gtfo beats fuzzy AD
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

    if wt is not None:
        if json_out:
            show_json_web(wt)
        elif plain:
            show_plain_web(wt, category, platform)
        else:
            show_rich_web(wt, category, platform)
        return

    if pt is not None:
        if json_out:
            show_json_postex(pt)
        elif plain:
            show_plain_postex(pt, category, platform)
        else:
            show_rich_postex(pt, category, platform)
        return

    if gtfo is not None:
        if json_out:
            show_json_gtfobin(gtfo)
        elif plain:
            show_plain_gtfobin(gtfo)
        else:
            show_rich_gtfobin(gtfo)
        return

    hints = suggest(query)
    if hints:
        hint_str = ", ".join(f"'{n}' ({k})" for n, k in hints)
        click.echo(f"No match for '{query}'. Did you mean: {hint_str}?", err=True)
    else:
        click.echo(f"No match for '{query}'.", err=True)
    sys.exit(1)
