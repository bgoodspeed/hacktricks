"""
Tests for GTFOBins integration in query.py, display.py, and the CLI.

Coverage goals:
  query_gtfobin       – exact binary lookup, fuzzy match, miss
  query_gtfo_func     – function-type lookup (shell, file-read, etc.)
  query_gtfo_ctx      – context lookup (sudo, suid, unprivileged)
  _resolve_gtfo_func  – alias resolution for function types
  _resolve_gtfo_ctx   – alias resolution for context types
  list_all_gtfo       – returns all binaries sorted
  gtfobins_index_counts – counts dict shape
  CLI --gtfo flag     – binary lookup, function lookup, list, JSON, plain
  CLI --func / --ctx  – filtering
  CLI general fallback – "hacktricks curl" hits GTFOBins when no other match
  CLI misses          – nonzero exit on no match
  suggest             – GTFOBins binary names appear in suggestions
"""

import json

import pytest
from click.testing import CliRunner

from hacktricks_cli.cli import main
from hacktricks_cli.query import (
    GTFOBin,
    GTFOFunction,
    _resolve_gtfo_ctx,
    _resolve_gtfo_func,
    gtfobins_index_counts,
    list_all_gtfo,
    query_gtfo_ctx,
    query_gtfo_func,
    query_gtfobin,
    suggest,
)


# ── _resolve_gtfo_func ────────────────────────────────────────────────────────

class TestResolveGtfoFunc:
    def test_exact_func_types(self):
        for ft in ("shell", "reverse-shell", "bind-shell", "file-read", "file-write",
                   "download", "upload", "command", "privilege-escalation",
                   "library-load", "inherit"):
            assert _resolve_gtfo_func(ft) == ft

    def test_alias_revshell(self):
        assert _resolve_gtfo_func("revshell") == "reverse-shell"

    def test_alias_rev_shell(self):
        assert _resolve_gtfo_func("rev-shell") == "reverse-shell"

    def test_alias_read(self):
        assert _resolve_gtfo_func("read") == "file-read"

    def test_alias_write(self):
        assert _resolve_gtfo_func("write") == "file-write"

    def test_alias_privesc(self):
        assert _resolve_gtfo_func("privesc") == "privilege-escalation"

    def test_alias_lpe(self):
        assert _resolve_gtfo_func("lpe") == "privilege-escalation"

    def test_alias_cmd(self):
        assert _resolve_gtfo_func("cmd") == "command"

    def test_alias_dl(self):
        assert _resolve_gtfo_func("dl") == "download"

    def test_alias_ul(self):
        assert _resolve_gtfo_func("ul") == "upload"

    def test_unknown_returns_none(self):
        assert _resolve_gtfo_func("zznotafunctype") is None


# ── _resolve_gtfo_ctx ─────────────────────────────────────────────────────────

class TestResolveGtfoCtx:
    def test_exact_contexts(self):
        for ctx in ("sudo", "suid", "unprivileged", "capabilities"):
            assert _resolve_gtfo_ctx(ctx) == ctx

    def test_alias_unpriv(self):
        assert _resolve_gtfo_ctx("unpriv") == "unprivileged"

    def test_alias_cap(self):
        assert _resolve_gtfo_ctx("cap") == "capabilities"

    def test_alias_caps(self):
        assert _resolve_gtfo_ctx("caps") == "capabilities"

    def test_alias_setuid(self):
        assert _resolve_gtfo_ctx("setuid") == "suid"

    def test_unknown_returns_none(self):
        assert _resolve_gtfo_ctx("zznotacontext") is None


# ── query_gtfobin ─────────────────────────────────────────────────────────────

class TestQueryGtfobin:
    def test_exact_lookup_curl(self):
        b = query_gtfobin("curl")
        assert b is not None
        assert b.name == "curl"

    def test_exact_lookup_python(self):
        b = query_gtfobin("python")
        assert b is not None
        assert b.name == "python"

    def test_exact_lookup_find(self):
        b = query_gtfobin("find")
        assert b is not None
        assert b.name == "find"

    def test_exact_lookup_gawk(self):
        b = query_gtfobin("gawk")
        assert b is not None
        assert b.name == "gawk"

    def test_case_insensitive(self):
        b = query_gtfobin("CURL")
        assert b is not None
        assert b.name == "curl"

    def test_fuzzy_typo(self):
        # "pythn" is close to "python"
        b = query_gtfobin("pythn")
        assert b is not None
        assert b.name == "python"

    def test_no_match_returns_none(self):
        assert query_gtfobin("zznotabinary123zzz") is None

    def test_returns_gtfobin_type(self):
        b = query_gtfobin("curl")
        assert isinstance(b, GTFOBin)

    def test_has_functions(self):
        b = query_gtfobin("curl")
        assert len(b.functions) > 0

    def test_functions_contain_gtfofunctions(self):
        b = query_gtfobin("curl")
        for func_type, entries in b.functions.items():
            assert isinstance(entries, list)
            for e in entries:
                assert isinstance(e, GTFOFunction)

    def test_python_has_shell(self):
        b = query_gtfobin("python")
        assert "shell" in b.functions

    def test_curl_has_file_read(self):
        b = query_gtfobin("curl")
        assert "file-read" in b.functions

    def test_curl_has_download(self):
        b = query_gtfobin("curl")
        assert "download" in b.functions

    def test_find_has_shell(self):
        b = query_gtfobin("find")
        assert "shell" in b.functions

    def test_function_entries_have_code(self):
        b = query_gtfobin("python")
        for entries in b.functions.values():
            for e in entries:
                assert e.code and len(e.code) > 0

    def test_function_entries_have_contexts(self):
        b = query_gtfobin("python")
        for entries in b.functions.values():
            for e in entries:
                assert isinstance(e.contexts, list)
                assert len(e.contexts) > 0

    def test_context_values_are_valid(self):
        valid = {"sudo", "suid", "unprivileged", "capabilities"}
        b = query_gtfobin("find")
        for entries in b.functions.values():
            for e in entries:
                for ctx in e.contexts:
                    assert ctx in valid


# ── query_gtfo_func ───────────────────────────────────────────────────────────

class TestQueryGtfoFunc:
    def test_shell_returns_list(self):
        binaries = query_gtfo_func("shell")
        assert isinstance(binaries, list)
        assert len(binaries) > 100  # GTFOBins has 228 shell binaries

    def test_file_read_returns_list(self):
        binaries = query_gtfo_func("file-read")
        assert len(binaries) > 100

    def test_reverse_shell_returns_list(self):
        binaries = query_gtfo_func("reverse-shell")
        assert len(binaries) > 5

    def test_shell_contains_python(self):
        names = {b.name for b in query_gtfo_func("shell")}
        assert "python" in names

    def test_shell_contains_gawk(self):
        names = {b.name for b in query_gtfo_func("shell")}
        assert "gawk" in names

    def test_file_read_contains_curl(self):
        names = {b.name for b in query_gtfo_func("file-read")}
        assert "curl" in names

    def test_download_contains_curl(self):
        names = {b.name for b in query_gtfo_func("download")}
        assert "curl" in names

    def test_returns_gtfobin_objects(self):
        for b in query_gtfo_func("shell")[:5]:
            assert isinstance(b, GTFOBin)

    def test_unknown_func_returns_empty(self):
        assert query_gtfo_func("zznotafunc") == []


# ── query_gtfo_ctx ────────────────────────────────────────────────────────────

class TestQueryGtfoCtx:
    def test_sudo_returns_list(self):
        binaries = query_gtfo_ctx("sudo")
        assert len(binaries) > 100

    def test_suid_returns_list(self):
        binaries = query_gtfo_ctx("suid")
        assert len(binaries) > 100

    def test_unprivileged_returns_list(self):
        binaries = query_gtfo_ctx("unprivileged")
        assert len(binaries) > 100

    def test_unknown_ctx_returns_empty(self):
        assert query_gtfo_ctx("zznotacontext") == []

    def test_returns_gtfobin_objects(self):
        for b in query_gtfo_ctx("sudo")[:5]:
            assert isinstance(b, GTFOBin)


# ── list_all_gtfo ─────────────────────────────────────────────────────────────

class TestListAllGtfo:
    def test_returns_list(self):
        binaries = list_all_gtfo()
        assert isinstance(binaries, list)

    def test_returns_many_binaries(self):
        binaries = list_all_gtfo()
        assert len(binaries) > 400

    def test_sorted_alphabetically(self):
        binaries = list_all_gtfo()
        names = [b.name for b in binaries]
        assert names == sorted(names)

    def test_contains_curl(self):
        names = {b.name for b in list_all_gtfo()}
        assert "curl" in names

    def test_contains_python(self):
        names = {b.name for b in list_all_gtfo()}
        assert "python" in names

    def test_contains_find(self):
        names = {b.name for b in list_all_gtfo()}
        assert "find" in names


# ── gtfobins_index_counts ─────────────────────────────────────────────────────

class TestGtfobinsIndexCounts:
    def test_returns_dict(self):
        counts = gtfobins_index_counts()
        assert isinstance(counts, dict)

    def test_has_total(self):
        counts = gtfobins_index_counts()
        assert "total" in counts
        assert counts["total"] > 400

    def test_has_by_function(self):
        counts = gtfobins_index_counts()
        assert "by_function" in counts
        assert isinstance(counts["by_function"], dict)

    def test_has_by_context(self):
        counts = gtfobins_index_counts()
        assert "by_context" in counts
        assert isinstance(counts["by_context"], dict)

    def test_shell_count_positive(self):
        counts = gtfobins_index_counts()
        assert counts["by_function"].get("shell", 0) > 100

    def test_sudo_count_positive(self):
        counts = gtfobins_index_counts()
        assert counts["by_context"].get("sudo", 0) > 100


# ── suggest ───────────────────────────────────────────────────────────────────

class TestSuggestGtfo:
    def test_valid_kinds_include_gtfo(self):
        valid_kinds = {"service", "ad", "postex", "privesc", "web", "gtfo"}
        for _, kind in suggest("curl", n=5):
            assert kind in valid_kinds

    def test_curl_suggests_gtfo(self):
        results = suggest("curl", n=5)
        kinds = {k for _, k in results}
        assert "gtfo" in kinds

    def test_gawk_suggests_gtfo(self):
        results = suggest("gawk", n=3)
        kinds = {k for _, k in results}
        assert "gtfo" in kinds


# ── CLI: --gtfo binary lookup ─────────────────────────────────────────────────

@pytest.fixture
def runner():
    return CliRunner()


class TestCLIGtfoBinaryLookup:
    def test_curl_exits_zero(self, runner):
        result = runner.invoke(main, ["--gtfo", "curl"])
        assert result.exit_code == 0

    def test_curl_shows_name(self, runner):
        result = runner.invoke(main, ["--gtfo", "curl"])
        assert "curl" in result.output

    def test_python_shows_shell(self, runner):
        result = runner.invoke(main, ["--gtfo", "python"])
        assert "SHELL" in result.output or "shell" in result.output.lower()

    def test_curl_shows_file_read(self, runner):
        result = runner.invoke(main, ["--gtfo", "curl"])
        assert "FILE READ" in result.output or "file-read" in result.output.lower()

    def test_find_shows_shell(self, runner):
        result = runner.invoke(main, ["--gtfo", "find"])
        assert "SHELL" in result.output or "shell" in result.output.lower()

    def test_no_match_exits_nonzero(self, runner):
        result = runner.invoke(main, ["--gtfo", "zznotabinaryzz"])
        assert result.exit_code != 0

    def test_no_match_message(self, runner):
        result = runner.invoke(main, ["--gtfo", "zznotabinaryzz"])
        assert "No GTFOBins entry" in result.output

    def test_plain_flag(self, runner):
        result = runner.invoke(main, ["--gtfo", "--plain", "curl"])
        assert result.exit_code == 0
        assert "curl" in result.output

    def test_json_flag(self, runner):
        result = runner.invoke(main, ["--gtfo", "--json", "curl"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "curl"
        assert "functions" in data

    def test_json_has_file_read(self, runner):
        result = runner.invoke(main, ["--gtfo", "--json", "curl"])
        data = json.loads(result.output)
        assert "file-read" in data["functions"]

    def test_json_entry_has_code(self, runner):
        result = runner.invoke(main, ["--gtfo", "--json", "python"])
        data = json.loads(result.output)
        shell_entries = data["functions"]["shell"]
        assert all("code" in e for e in shell_entries)

    def test_json_entry_has_contexts(self, runner):
        result = runner.invoke(main, ["--gtfo", "--json", "python"])
        data = json.loads(result.output)
        for func_entries in data["functions"].values():
            for e in func_entries:
                assert "contexts" in e


# ── CLI: --gtfo function-type lookup ─────────────────────────────────────────

class TestCLIGtfoFuncLookup:
    def test_shell_func_by_query(self, runner):
        result = runner.invoke(main, ["--gtfo", "shell"])
        assert result.exit_code == 0
        assert "SHELL" in result.output or "shell" in result.output.lower()

    def test_file_read_func_by_query(self, runner):
        result = runner.invoke(main, ["--gtfo", "file-read"])
        assert result.exit_code == 0

    def test_shell_alias_revshell(self, runner):
        result = runner.invoke(main, ["--gtfo", "revshell"])
        assert result.exit_code == 0

    def test_func_flag_without_query(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "shell"])
        assert result.exit_code == 0
        assert "SHELL" in result.output

    def test_func_flag_file_read(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "file-read"])
        assert result.exit_code == 0
        assert "FILE READ" in result.output

    def test_func_flag_with_ctx(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "shell", "--ctx", "suid"])
        assert result.exit_code == 0
        assert "suid" in result.output.lower()

    def test_func_plain(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "shell", "--plain"])
        assert result.exit_code == 0

    def test_func_json(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "shell", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["function_type"] == "shell"
        assert data["count"] > 100
        assert "binaries" in data

    def test_func_json_entries_have_code(self, runner):
        result = runner.invoke(main, ["--gtfo", "--func", "file-read", "--json"])
        data = json.loads(result.output)
        for b in data["binaries"][:5]:
            for e in b["entries"]:
                assert "code" in e


# ── CLI: --list --gtfo ────────────────────────────────────────────────────────

class TestCLIGtfoList:
    def test_list_exits_zero(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo"])
        assert result.exit_code == 0

    def test_list_contains_curl(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo"])
        assert "curl" in result.output

    def test_list_contains_python(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo"])
        assert "python" in result.output

    def test_list_plain(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo", "--plain"])
        assert result.exit_code == 0

    def test_list_json(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 400
        names = [d["name"] for d in data]
        assert "curl" in names

    def test_list_json_has_functions(self, runner):
        result = runner.invoke(main, ["--list", "--gtfo", "--json"])
        data = json.loads(result.output)
        for entry in data[:5]:
            assert "functions" in entry
            assert isinstance(entry["functions"], list)


# ── CLI: general fallback to GTFOBins ────────────────────────────────────────

class TestCLIGtfoFallback:
    def test_curl_general_search_hits_gtfo(self, runner):
        """curl has no service/AD/postex/privesc/web entry → falls back to GTFOBins."""
        result = runner.invoke(main, ["curl"])
        assert result.exit_code == 0
        assert "curl" in result.output

    def test_gawk_general_search_hits_gtfo(self, runner):
        result = runner.invoke(main, ["gawk"])
        assert result.exit_code == 0
        assert "gawk" in result.output

    def test_vim_general_search_hits_gtfo(self, runner):
        result = runner.invoke(main, ["vim"])
        assert result.exit_code == 0

    def test_general_fallback_shows_functions(self, runner):
        result = runner.invoke(main, ["python"])
        assert result.exit_code == 0


# ── CLI: --info includes GTFOBins ─────────────────────────────────────────────

class TestCLIInfoGtfo:
    def test_info_includes_gtfobins(self, runner):
        result = runner.invoke(main, ["--info"])
        assert result.exit_code == 0
        assert "gtfo" in result.output.lower() or "total" in result.output

    def test_info_json_includes_gtfobins(self, runner):
        result = runner.invoke(main, ["--info", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "gtfobins_counts" in data
        assert data["gtfobins_counts"]["total"] > 400
