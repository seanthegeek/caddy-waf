#!/usr/bin/env python3
"""Unit tests for get_owasp_rules.py (run: python3 -m unittest test_get_owasp_rules).

No network access and no Go toolchain needed: the translation tests use the
Python heuristic validator (``--re2check python``); the one test that needs
RE2 is skipped when ``go`` is not on PATH.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import get_owasp_rules as owasp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

SAMPLE_CONF = r'''
# A comment line and a SecAction that must be ignored.
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,skipAfter:END"

SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)union\s+select" \
    "id:942100,\
    phase:2,\
    block,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack, with a comma',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"

SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners.data" \
    "id:913100,phase:1,block,t:none,msg:'Scanner',tag:'paranoia-level/1',severity:'CRITICAL'"

SecRule ARGS "@rx ^https?://\d+\.\d+$" \
    "id:931100,phase:2,block,t:none,msg:'RFI',tag:'paranoia-level/2',severity:'CRITICAL'"

SecRule REQUEST_HEADERS:Host "@rx ^[\d.:]+$" \
    "id:920350,phase:1,block,t:none,msg:'Host is IP',tag:'paranoia-level/1',severity:'WARNING'"

SecRule REQUEST_HEADERS:Host "@rx ^$" \
    "id:920290,phase:1,block,t:none,msg:'Empty Host',severity:'WARNING'"

SecRule ARGS "@rx a" "id:920170,phase:2,block,chain,msg:'Chained parent',severity:'CRITICAL'"
    SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" "t:none"

SecRule ARGS "@detectSQLi" "id:942101,phase:2,block,msg:'libinjection',severity:'CRITICAL'"

SecRule ARGS "@rx x" "id:934100,phase:2,block,t:base64Decode,msg:'needs decode',severity:'CRITICAL'"

SecRule ARGS "@rx ^(?:%{tx.allowed})$" "id:920420,phase:1,block,msg:'macro',severity:'CRITICAL'"

SecRule TX:1 "@rx y" "id:942999,phase:2,block,msg:'no target',severity:'CRITICAL'"

SecRule RESPONSE_BODY "@pm password root" \
    "id:950100,phase:4,block,t:none,msg:'Leak with \"escaped quote\" in msg',severity:'ERROR'"

SecRule ARGS "@rx (?i)ab[\"']c" "id:942200,phase:2,block,t:none,t:lowercase,t:removeWhitespace,t:cmdLine,msg:'Quote',severity:'NOTICE'"
'''


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.rules = owasp.parse_seclang(SAMPLE_CONF, "sample.conf")
        self.by_id = {r.id: r for r in self.rules}

    def test_continuations_and_comments(self):
        # 14 SecRule directives, 1 of them a chain child folded into its parent.
        self.assertEqual(len(self.rules), 13)
        self.assertNotIn(None, self.by_id)

    def test_actions_split_outside_quotes(self):
        r = self.by_id["942100"]
        self.assertEqual(r.first_action("msg"), "SQL Injection Attack, with a comma")
        self.assertEqual(r.action_values("t"), ["none", "utf8toUnicode", "urlDecodeUni", "removeNulls"])
        self.assertEqual(r.action_values("tag"), ["attack-sqli", "paranoia-level/1"])
        self.assertEqual(r.paranoia_level, 1)
        self.assertEqual(r.first_action("severity"), "CRITICAL")
        self.assertEqual(r.first_action("phase"), "2")

    def test_variables(self):
        names = [(v.name, v.selector, v.negated) for v in self.by_id["942100"].variables]
        self.assertEqual(names, [
            ("REQUEST_COOKIES", None, False),
            ("REQUEST_COOKIES", "/__utm/", True),
            ("REQUEST_COOKIES_NAMES", None, False),
            ("ARGS_NAMES", None, False),
            ("ARGS", None, False),
            ("XML", "/*", False),
        ])

    def test_operator_parsing(self):
        self.assertEqual(self.by_id["942100"].operator, "rx")
        self.assertEqual(self.by_id["942100"].argument, r"(?i)union\s+select")
        self.assertEqual(self.by_id["913100"].operator, "pmFromFile")
        self.assertEqual(self.by_id["942101"].operator, "detectSQLi")

    def test_chain_grouping(self):
        parent = self.by_id["920170"]
        self.assertEqual(len(parent.children), 1)
        child = parent.children[0]
        self.assertTrue(child.negated)
        self.assertEqual(child.variables[0].selector, "Content-Length")

    def test_escaped_quote_inside_quoted_string(self):
        self.assertEqual(self.by_id["950100"].first_action("msg"), 'Leak with "escaped quote" in msg')
        self.assertEqual(self.by_id["942200"].argument, "(?i)ab[\"']c")

    def test_default_paranoia_level(self):
        self.assertEqual(self.by_id["920290"].paranoia_level, 1)


class MappingTests(unittest.TestCase):
    def test_map_targets(self):
        targets, dropped, notes = owasp.map_targets(owasp.parse_variables(
            "REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*|TX:1|&ARGS"))
        self.assertEqual(targets, ["COOKIES", "ARGS", "BODY"])
        self.assertEqual(dropped, ["TX:1", "&ARGS"])
        self.assertTrue(any("exclusion !REQUEST_COOKIES:/__utm/" in n for n in notes))
        self.assertTrue(any("XML:/* widened to BODY" in n for n in notes))

    def test_selector_targets(self):
        targets, _, _ = owasp.map_targets(owasp.parse_variables("REQUEST_HEADERS:User-Agent|REQUEST_COOKIES:sid|ARGS:q"))
        self.assertEqual(targets, ["HEADERS:User-Agent", "COOKIES:sid", "URL_PARAM:q"])

    def test_host_header_maps_to_host_target(self):
        targets, _, _ = owasp.map_targets(owasp.parse_variables("REQUEST_HEADERS:Host"))
        self.assertEqual(targets, ["HOST"])

    def test_regex_selector_widens(self):
        targets, _, notes = owasp.map_targets(owasp.parse_variables("REQUEST_HEADERS:/^X-/"))
        self.assertEqual(targets, ["HEADERS"])
        self.assertTrue(any("widened" in n for n in notes))

    def test_transformations(self):
        chain, notes, bad = owasp.map_transformations(["none", "urlDecodeUni", "removeWhitespace", "cmdLine", "lowercase"])
        self.assertIsNone(bad)
        self.assertEqual(chain, ["urlDecodeUni", "compressWhitespace", "lowercase"])
        self.assertEqual(len(notes), 2)

    def test_none_resets_chain(self):
        chain, _, _ = owasp.map_transformations(["lowercase", "none", "removeNulls"])
        self.assertEqual(chain, ["removeNulls"])

    def test_semantic_transformation_rejected(self):
        _, _, bad = owasp.map_transformations(["base64Decode"])
        self.assertEqual(bad, "base64Decode")

    def test_phrases_to_pattern_is_sorted_and_escaped(self):
        pattern = owasp.phrases_to_pattern(["bin/cat", "$HOME", "a.b", "bin/cat"])
        self.assertEqual(pattern, r"(?i)(?:\$HOME|a\.b|bin/cat)")

    def test_relax_anchors_only_for_collection_targets(self):
        relaxed, note = owasp.relax_anchors(r"(?i)^https?://x$", ["ARGS", "BODY"])
        self.assertEqual(relaxed, r'(?i)(?:^|[&="]|:\s*)https?://x(?:$|[&;"])')
        self.assertIn("^ and $", note)
        same, note = owasp.relax_anchors(r"^https?://x$", ["PATH", "HEADERS:Host"])
        self.assertEqual(same, r"^https?://x$")
        self.assertIsNone(note)
        escaped, note = owasp.relax_anchors(r"price\$", ["ARGS"])
        self.assertEqual(escaped, r"price\$")
        self.assertIsNone(note)


class TranslationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "sample.conf"), "w") as fh:
            fh.write(SAMPLE_CONF)
        with open(os.path.join(self.tmp, "scanners.data"), "w") as fh:
            fh.write("# comment\nnikto\nsqlmap\n\nNessus\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def translate(self, tuning=None):
        return owasp.translate_directory(self.tmp, "python", REPO_ROOT, tuning)

    def test_translation_and_skips(self):
        translated, skipped, totals = self.translate()
        self.assertEqual(totals["sample.conf"], 13)
        ported = {t.rule["id"]: t for t in translated}
        self.assertEqual(sorted(ported), ["crs-913100", "crs-920350", "crs-931100", "crs-942100", "crs-942200", "crs-950100"])

        sqli = ported["crs-942100"].rule
        self.assertEqual(sqli["targets"], ["COOKIES", "ARGS", "BODY"])
        self.assertEqual(sqli["transformations"], ["urlDecodeUni", "removeNulls"])
        self.assertEqual(sqli["action"], "log")
        self.assertEqual(sqli["score"], 5)
        self.assertEqual(sqli["phase"], 2)
        self.assertEqual(sqli["description"], "OWASP CRS 942100 PL1: SQL Injection Attack, with a comma")
        self.assertEqual(list(sqli), ["id", "phase", "pattern", "targets", "severity", "action", "score", "description", "transformations"])

        scanner = ported["crs-913100"].rule
        self.assertEqual(scanner["pattern"], "(?i)(?:Nessus|nikto|sqlmap)")
        self.assertEqual(scanner["targets"], ["HEADERS:User-Agent"])
        self.assertEqual(scanner["transformations"], [])

        rfi = ported["crs-931100"]
        self.assertEqual(rfi.paranoia_level, 2)
        self.assertTrue(rfi.rule["pattern"].startswith('(?:^|[&="]|:\\s*)https?://'))
        self.assertTrue(rfi.rule["pattern"].endswith('(?:$|[&;"])'))
        self.assertTrue(rfi.rule["transformations"], ["urlDecodeUni"])

        self.assertEqual(ported["crs-920350"].rule["targets"], ["HOST"])
        self.assertEqual(ported["crs-920350"].rule["pattern"], r"^[\d.:]+$")  # single value: anchors kept

        leak = ported["crs-950100"].rule
        self.assertEqual(leak["phase"], 4)
        self.assertEqual(leak["pattern"], "(?i)(?:password|root)")
        self.assertEqual(leak["score"], 4)

        quote = ported["crs-942200"]
        self.assertEqual(quote.rule["transformations"], ["urlDecodeUni", "lowercase", "compressWhitespace"])
        self.assertEqual(quote.rule["score"], 2)
        self.assertTrue(any("t:cmdLine dropped" in n for n in quote.notes))
        self.assertTrue(any("t:removeWhitespace approximated" in n for n in quote.notes))

        reasons = {s.id: s.category for s in skipped}
        self.assertEqual(reasons, {
            "942011": "control/flow rule",
            "920290": "presence check",
            "920170": "chained rule",
            "942101": "non-regex operator",
            "934100": "unsupported transformation",
            "920420": "macro expansion",
            "942999": "no mappable target",
        })

    def test_tuning(self):
        path = os.path.join(self.tmp, "tuning.txt")
        with open(path, "w") as fh:
            fh.write("942100 remove-target body,COOKIES  # raw body\n913100 remove  # noisy\n931100\n"
                     "950100 remove-target response_body  # selector-free\n")
        tuning = owasp.read_tuning(path, "920350")
        translated, skipped, _ = self.translate(tuning)
        ported = {t.rule["id"]: t for t in translated}
        self.assertEqual(sorted(ported), ["crs-942100", "crs-942200"])
        self.assertEqual(ported["crs-942100"].rule["targets"], ["ARGS"])
        self.assertEqual({s.id: s.detail for s in skipped}["950100"], "every target removed")
        self.assertTrue(any("target BODY removed by tuning: raw body" in n for n in ported["crs-942100"].notes))
        by_id = {s.id: s for s in skipped}
        self.assertEqual(by_id["913100"].category, "removed by tuning")
        self.assertEqual(by_id["913100"].detail, "noisy")
        self.assertEqual(by_id["920350"].detail, "listed in --exclude")
        self.assertEqual(by_id["931100"].category, "removed by tuning")

    def test_tuning_keeps_selector_case(self):
        path = os.path.join(self.tmp, "tuning.txt")
        with open(path, "w") as fh:
            fh.write("913100 remove-target headers:User-Agent\n")
        tuning = owasp.read_tuning(path, None)
        self.assertEqual(tuning.remove_targets["913100"], {"HEADERS:User-Agent": "tuning.txt:1"})
        _, skipped, _ = self.translate(tuning)
        self.assertEqual({s.id: s.category for s in skipped}["913100"], "removed by tuning")

    def test_tuning_syntax_error(self):
        path = os.path.join(self.tmp, "tuning.txt")
        with open(path, "w") as fh:
            fh.write("942100 frobnicate BODY\n")
        with self.assertRaises(SystemExit):
            owasp.read_tuning(path, None)

    def test_block_severity(self):
        translated, _, _ = self.translate()
        owasp.apply_block_severity(translated, "ERROR")
        actions = {t.rule["id"]: t.rule["action"] for t in translated}
        self.assertEqual(actions["crs-942100"], "block")  # CRITICAL
        self.assertEqual(actions["crs-950100"], "block")  # ERROR
        self.assertEqual(actions["crs-920350"], "log")    # WARNING
        self.assertEqual(actions["crs-942200"], "log")    # NOTICE

    def test_python_validator_rejects_pcre_only_syntax(self):
        failures = owasp.python_heuristic_failures([
            ("lookahead", r"a(?=b)"), ("backref", r"(a)\1"), ("escaped-qmark-plus", r"x\?+$"), ("plain", r"a+b*")])
        self.assertEqual(sorted(failures), ["backref", "lookahead"])

    @unittest.skipUnless(shutil.which("go"), "go toolchain not installed")
    def test_go_validator_rejects_what_re2_rejects(self):
        failures = owasp.re2_validate([("ok", r"(?i)a|b"), ("look", r"a(?=b)"), ("big", r"a{1001}")], "go", REPO_ROOT)
        self.assertEqual(sorted(failures), ["big", "look"])

    def test_auto_mode_falls_back_without_the_helper(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            failures = owasp.re2_validate([("look", r"a(?=b)"), ("ok", "a")], "auto", self.tmp)
        self.assertEqual(sorted(failures), ["look"])
        self.assertIn("falling back", err.getvalue())

    def test_go_mode_requires_the_helper(self):
        with self.assertRaises(SystemExit):
            owasp.re2_validate([("ok", "a")], "go", self.tmp)

    def test_report(self):
        translated, skipped, totals = self.translate()
        report = os.path.join(self.tmp, "COVERAGE.md")
        owasp.write_report(report, "v0-test", translated, skipped, totals, {os.path.join(self.tmp, "crs-pl1.json"): 4})
        text = open(report).read()
        self.assertIn("# OWASP CRS v0-test translation coverage", text)
        self.assertIn("- CRS rules with an id: 13", text)
        self.assertIn("`crs-pl1.json`: 4 rules", text)
        owasp.write_report(report, "v0-test", translated, skipped, totals, {"one.json": 1}, "my-tuning.txt")
        text = open(report).read()
        self.assertIn("`one.json`: 1 rule\n", text)
        self.assertIn("`my-tuning.txt` (passed with `--tuning`)", text)
        self.assertIn("| chained rule | 1 |", text)
        self.assertIn("| 920170 | sample.conf | chained rule: caddy-waf has no rule chaining |", text)
        self.assertIn("| crs-942200 | sample.conf |", text)

    def test_cli_writes_bundles_and_report(self):
        out = os.path.join(self.tmp, "out", "crs-pl1.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = owasp.main(["--source", self.tmp, "--output", out, "--paranoia-level", "2", "--re2check", "python"])
        self.assertEqual(rc, 0)
        rules = json.load(open(out))
        self.assertEqual([r["id"] for r in rules], ["crs-913100", "crs-920350", "crs-931100", "crs-942100", "crs-942200"])
        response = json.load(open(os.path.join(self.tmp, "out", "crs-pl1-response.json")))
        self.assertEqual([r["id"] for r in response], ["crs-950100"])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "out", "COVERAGE.md")))

    def test_cli_output_dir_splits_by_paranoia_level(self):
        out_dir = os.path.join(self.tmp, "bundles")
        with contextlib.redirect_stdout(io.StringIO()):
            owasp.main(["--source", self.tmp, "--output-dir", out_dir, "--re2check", "python"])
        pl1 = json.load(open(os.path.join(out_dir, "crs-pl1.json")))
        pl2 = json.load(open(os.path.join(out_dir, "crs-pl2.json")))
        self.assertEqual([r["id"] for r in pl2], ["crs-931100"])
        self.assertNotIn("crs-931100", [r["id"] for r in pl1])
        self.assertTrue(os.path.exists(os.path.join(out_dir, "crs-pl1-response.json")))
        self.assertFalse(os.path.exists(os.path.join(out_dir, "crs-pl2-response.json")))
        self.assertEqual(json.load(open(os.path.join(out_dir, "crs-pl3.json"))), [])


class ScriptInvocationTest(unittest.TestCase):
    def test_help_runs(self):
        proc = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "get_owasp_rules.py"), "--help"],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--paranoia-level", proc.stdout)


if __name__ == "__main__":
    unittest.main()
