"""
Tests for the fuzzy/normalized matching layer in query.py, and the CLI's
"did you mean?" output.

Coverage goals:
  _normalize          – separator stripping, case folding, edge cases
  _find_slug          – exact / normalized / fuzzy-original / fuzzy-normalized
  query_service       – service-index lookups via each match path
  query_technique     – AD-index lookups
  query_postex        – postex-index lookups
  query_privesc       – privesc-index lookups
  query_web           – web-index lookups
  suggest             – cross-index scoring and dedup
  CLI (click runner)  – end-to-end: hits, near-misses, "did you mean?" message
"""
import pytest
from click.testing import CliRunner

from hacktricks_cli.cli import main
from hacktricks_cli.query import (
    _find_slug,
    _normalize,
    query_postex,
    query_privesc,
    query_service,
    query_technique,
    query_web,
    suggest,
)


# ── _normalize ─────────────────────────────────────────────────────────────────

class TestNormalize:
    def test_strips_hyphens(self):
        assert _normalize("active-directory") == "activedirectory"

    def test_strips_underscores(self):
        assert _normalize("active_directory") == "activedirectory"

    def test_strips_spaces(self):
        assert _normalize("active directory") == "activedirectory"

    def test_strips_dots(self):
        assert _normalize("opc.ua") == "opcua"

    def test_mixed_separators(self):
        assert _normalize("active - directory") == "activedirectory"

    def test_lowercases(self):
        assert _normalize("SMB") == "smb"

    def test_already_clean(self):
        assert _normalize("smb") == "smb"

    def test_empty_string(self):
        assert _normalize("") == ""

    def test_multiple_consecutive_separators(self):
        assert _normalize("foo--bar") == "foobar"

    def test_equivalences(self):
        # All these forms should normalize to the same thing
        variants = ["active-directory", "active_directory", "active directory", "ActiveDirectory"]
        normed = {_normalize(v) for v in variants}
        assert len(normed) == 1


# ── _find_slug ─────────────────────────────────────────────────────────────────

class TestFindSlug:
    CANDIDATES = {
        "shadow-credentials": [
            "shadow-credentials",
            "shadow credentials",
            "key trust abuse",
            "msds-keycredentiallink abuse",
            "pywhisker",
            "whisker",
        ],
        "kerberoast": [
            "kerberoast",
            "kerberoasting",
            "spn roasting",
            "tgs roasting",
        ],
        "smb": ["smb", "server message block", "samba"],
    }

    def test_exact_slug(self):
        assert _find_slug("kerberoast", self.CANDIDATES) == "kerberoast"

    def test_exact_name(self):
        assert _find_slug("kerberoasting", self.CANDIDATES) == "kerberoast"

    def test_exact_alias(self):
        assert _find_slug("pywhisker", self.CANDIDATES) == "shadow-credentials"

    def test_case_insensitive_exact(self):
        assert _find_slug("SMB", self.CANDIDATES) == "smb"

    def test_normalized_match_hyphen(self):
        # "shadow credentials" (space) matches slug "shadow-credentials"
        assert _find_slug("shadowcredentials", self.CANDIDATES) == "shadow-credentials"

    def test_normalized_match_space(self):
        assert _find_slug("spnroasting", self.CANDIDATES) == "kerberoast"

    def test_fuzzy_typo(self):
        # One letter off
        assert _find_slug("kerberosting", self.CANDIDATES) == "kerberoast"

    def test_fuzzy_normalized_typo(self):
        # Hyphenated slug with a typo
        assert _find_slug("shadowcredentals", self.CANDIDATES) == "shadow-credentials"

    def test_no_match_returns_none(self):
        assert _find_slug("zznotarealthingzz", self.CANDIDATES) is None

    def test_empty_candidates(self):
        assert _find_slug("anything", {}) is None


# ── query_service ──────────────────────────────────────────────────────────────

class TestQueryService:
    def test_exact_slug(self):
        svc = query_service("smb")
        assert svc is not None
        assert svc.slug == "smb"

    def test_exact_alias(self):
        # ftp has aliases: ['tftp', 'sftp']
        svc = query_service("tftp")
        assert svc is not None
        assert svc.slug == "ftp"

    def test_case_insensitive(self):
        assert query_service("SMB") is not None

    def test_hyphenated_slug_normalized(self):
        # slug is "android-adb"; typing "androidadb" should resolve it
        svc = query_service("androidadb")
        assert svc is not None
        assert svc.slug == "android-adb"

    def test_spaced_slug_normalized(self):
        # slug is "docker-registry"; "docker registry" should resolve
        svc = query_service("docker registry")
        assert svc is not None
        assert svc.slug == "docker-registry"

    def test_fuzzy_typo(self):
        # "smbv" is close to "smb"
        svc = query_service("smbv")
        assert svc is not None
        assert svc.slug == "smb"

    def test_no_match_returns_none(self):
        assert query_service("zznotarealservicezz") is None

    def test_returns_service_object(self):
        svc = query_service("ftp")
        assert svc.slug == "ftp"
        assert svc.name == "FTP"
        assert isinstance(svc.ports, list)


# ── query_technique (AD) ───────────────────────────────────────────────────────

class TestQueryTechnique:
    def test_exact_slug(self):
        t = query_technique("kerberoast")
        assert t is not None
        assert t.slug == "kerberoast"

    def test_exact_alias(self):
        # kerberoast aliases: ['SPN roasting', 'TGS roasting', ...]
        t = query_technique("spn roasting")
        assert t is not None
        assert t.slug == "kerberoast"

    def test_case_insensitive(self):
        assert query_technique("Kerberoast") is not None

    def test_normalized_slug(self):
        # slug "shadow-credentials" via "shadowcredentials"
        t = query_technique("shadowcredentials")
        assert t is not None
        assert t.slug == "shadow-credentials"

    def test_normalized_alias(self):
        # alias "AD CS" → slug "ad-certificates"
        t = query_technique("adcs")
        assert t is not None
        assert t.slug == "ad-certificates"

    def test_fuzzy_typo(self):
        t = query_technique("kerberosting")
        assert t is not None
        assert t.slug == "kerberoast"

    def test_no_match_returns_none(self):
        assert query_technique("zznotarealtechniquezz") is None


# ── query_postex ───────────────────────────────────────────────────────────────

class TestQueryPostex:
    def test_exact_slug(self):
        p = query_postex("base64-exfil")
        assert p is not None
        assert p.slug == "base64-exfil"

    def test_exact_alias(self):
        # http-exfil aliases include 'wget'
        p = query_postex("wget")
        assert p is not None
        assert p.slug == "http-exfil"

    def test_normalized_slug(self):
        # slug "base64-exfil" → "base64exfil"
        p = query_postex("base64exfil")
        assert p is not None
        assert p.slug == "base64-exfil"

    def test_fuzzy_alias(self):
        # "bitsadmn" ≈ "bitsadmin" (alias of http-exfil)
        p = query_postex("bitsadmn")
        assert p is not None
        assert p.slug == "http-exfil"

    def test_no_match_returns_none(self):
        assert query_postex("zznotarealposttechzz") is None


# ── query_privesc ──────────────────────────────────────────────────────────────

class TestQueryPrivesc:
    def test_exact_slug(self):
        p = query_privesc("linux-sudo")
        assert p is not None
        assert p.slug == "linux-sudo"

    def test_exact_alias(self):
        # linux-sudo aliases include 'sudo'
        p = query_privesc("sudo")
        assert p is not None
        assert p.slug == "linux-sudo"

    def test_normalized_slug(self):
        # slug "linux-suid" → "linuxsuid"
        p = query_privesc("linuxsuid")
        assert p is not None
        assert p.slug == "linux-suid"

    def test_normalized_alias(self):
        # alias "linux enum" (space) → "linuxenum"
        p = query_privesc("linuxenum")
        assert p is not None
        assert p.slug == "linux-enum"

    def test_fuzzy_typo(self):
        # "sudoabuse" close to alias "sudo privesc" / name "Sudo Abuse"
        p = query_privesc("sudoabuse")
        assert p is not None
        assert p.slug == "linux-sudo"

    def test_no_match_returns_none(self):
        assert query_privesc("zznotarealprivesczz") is None


# ── query_web ──────────────────────────────────────────────────────────────────

class TestQueryWeb:
    def test_exact_slug(self):
        w = query_web("sql-injection")
        assert w is not None
        assert w.slug == "sql-injection"

    def test_exact_alias(self):
        # sql-injection aliases: ['sqli', 'sql injection', ...]
        w = query_web("sqli")
        assert w is not None
        assert w.slug == "sql-injection"

    def test_normalized_slug(self):
        # slug "xss-cross-site-scripting" → "xsscrosssitescripting"
        w = query_web("xsscrosssitescripting")
        assert w is not None
        assert w.slug == "xss-cross-site-scripting"

    def test_normalized_alias(self):
        # alias "cross site scripting" → "crosssitescripting"
        w = query_web("crosssitescripting")
        assert w is not None
        assert w.slug == "xss-cross-site-scripting"

    def test_normalized_typo_slug(self):
        # "sqli-injetion" is "sqliinjetion" normalized — close to "sqlinjection"
        w = query_web("sqliinjetion")
        assert w is not None
        assert w.slug == "sql-injection"

    def test_no_match_returns_none(self):
        assert query_web("zznotarealwebvulnzz") is None


# ── suggest ────────────────────────────────────────────────────────────────────

class TestSuggest:
    def test_returns_list(self):
        results = suggest("kerberoast")
        assert isinstance(results, list)

    def test_respects_n(self):
        results = suggest("kerberoast", n=2)
        assert len(results) <= 2

    def test_result_format(self):
        results = suggest("smb")
        assert all(isinstance(name, str) and isinstance(kind, str) for name, kind in results)

    def test_valid_kinds(self):
        valid_kinds = {"service", "ad", "postex", "privesc", "web"}
        for _, kind in suggest("smb", n=5):
            assert kind in valid_kinds

    def test_near_miss_returns_relevant(self):
        # "kerberosting" should suggest Kerberoasting
        results = suggest("kerberosting", n=3)
        names = [n for n, _ in results]
        assert any("Kerberoast" in name or "Kerberos" in name for name in names)

    def test_no_duplicates(self):
        results = suggest("smb", n=5)
        keys = [(n, k) for n, k in results]
        assert len(keys) == len(set(keys))

    def test_totally_unknown_returns_list(self):
        # Should not raise; may return something or empty
        results = suggest("zzzzunknownzzzz", n=3)
        assert isinstance(results, list)

    def test_normalized_near_miss(self):
        # "shadowcredentals" should surface Shadow Credentials
        results = suggest("shadowcredentals", n=3)
        names = [n for n, _ in results]
        assert any("Shadow" in name for name in names)


# ── CLI integration ────────────────────────────────────────────────────────────

@pytest.fixture
def runner():
    return CliRunner()


class TestCLIHits:
    def test_port_lookup(self, runner):
        result = runner.invoke(main, ["445"])
        assert result.exit_code == 0
        assert "SMB" in result.output

    def test_service_by_slug(self, runner):
        result = runner.invoke(main, ["smb"])
        assert result.exit_code == 0
        assert "SMB" in result.output

    def test_service_by_alias(self, runner):
        # 'tftp' is an alias for ftp
        result = runner.invoke(main, ["tftp"])
        assert result.exit_code == 0
        assert "FTP" in result.output

    def test_service_normalized(self, runner):
        result = runner.invoke(main, ["dockerregistry"])
        assert result.exit_code == 0
        assert "Docker" in result.output

    def test_service_fuzzy(self, runner):
        result = runner.invoke(main, ["smbv"])
        assert result.exit_code == 0
        assert "SMB" in result.output

    def test_ad_flag_technique(self, runner):
        result = runner.invoke(main, ["--ad", "kerberoast"])
        assert result.exit_code == 0
        assert "Kerberoast" in result.output

    def test_ad_normalized(self, runner):
        result = runner.invoke(main, ["--ad", "shadowcredentials"])
        assert result.exit_code == 0
        assert "Shadow" in result.output

    def test_postex_normalized(self, runner):
        result = runner.invoke(main, ["base64exfil"])
        assert result.exit_code == 0

    def test_privesc_by_alias(self, runner):
        result = runner.invoke(main, ["sudo"])
        assert result.exit_code == 0
        assert "Sudo" in result.output

    def test_privesc_normalized(self, runner):
        result = runner.invoke(main, ["linuxsuid"])
        assert result.exit_code == 0
        assert "SUID" in result.output

    def test_web_by_alias(self, runner):
        result = runner.invoke(main, ["sqli"])
        assert result.exit_code == 0
        assert "SQL" in result.output

    def test_web_normalized(self, runner):
        result = runner.invoke(main, ["crosssitescripting"])
        assert result.exit_code == 0
        assert "XSS" in result.output


class TestCLIMisses:
    def test_no_match_exits_nonzero(self, runner):
        result = runner.invoke(main, ["zzzzunknownzzzz"])
        assert result.exit_code != 0

    def test_no_match_message(self, runner):
        result = runner.invoke(main, ["zzzzunknownzzzz"])
        assert "No match" in result.output

    def test_did_you_mean_shown_on_near_miss(self, runner):
        # "kerberosting" is close enough to surface a suggestion
        result = runner.invoke(main, ["kerberosting"])
        # Either it found a match (exit 0) or it suggested alternatives
        if result.exit_code != 0:
            assert "Did you mean" in result.output

    def test_did_you_mean_format(self, runner):
        # Force a miss that should trigger suggestions
        result = runner.invoke(main, ["blahblahblah"])
        if result.exit_code != 0 and "Did you mean" in result.output:
            # Should contain at least one (kind) annotation
            assert "(" in result.output and ")" in result.output

    def test_ad_flag_no_match(self, runner):
        result = runner.invoke(main, ["--ad", "zznotarealtechniquezz"])
        assert result.exit_code != 0
        assert "No AD technique" in result.output

    def test_postex_flag_no_match(self, runner):
        result = runner.invoke(main, ["--postex", "zznotarealposttechzz"])
        assert result.exit_code != 0

    def test_privesc_flag_no_match(self, runner):
        result = runner.invoke(main, ["--privesc", "zznotarealprivesczz"])
        assert result.exit_code != 0

    def test_web_flag_no_match(self, runner):
        result = runner.invoke(main, ["--web", "zznotarealwebvulnzz"])
        assert result.exit_code != 0


class TestCLIOutputModes:
    def test_plain_flag(self, runner):
        result = runner.invoke(main, ["--plain", "smb"])
        assert result.exit_code == 0

    def test_json_flag(self, runner):
        import json
        result = runner.invoke(main, ["--json", "smb"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Single-service result is a dict; multi-service (port lookup) is a list
        slug = data["slug"] if isinstance(data, dict) else data[0]["slug"]
        assert slug == "smb"

    def test_list_flag(self, runner):
        result = runner.invoke(main, ["--list"])
        assert result.exit_code == 0

    def test_info_flag(self, runner):
        result = runner.invoke(main, ["--info"])
        assert result.exit_code == 0
        assert "service_count" in result.output or "version" in result.output
