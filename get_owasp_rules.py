#!/usr/bin/env python3
"""Translate OWASP ModSecurity Core Rule Set (CRS) SecLang rules into caddy-waf JSON.

caddy-waf matches one Go RE2 regular expression against one or more request
targets, adds the rule's score and decides on block/log. ModSecurity's SecLang
is a much larger language (operators, chained rules, transaction variables,
structured body parsers, paranoia-level control flow). This script ports the
subset that maps onto the caddy-waf model and writes a coverage report that
says exactly what it could not port, so the gap is documented rather than
hidden. The result is CRS-informed coverage, not CRS parity.

What is ported
    * ``@rx`` rules: the regex is used as-is after RE2 validation.
    * ``@pm`` / ``@pmFromFile`` rules: the keyword list becomes a
      case-insensitive alternation.
    * ``t:`` transformation chains, mapped onto caddy-waf's ``transformations``
      field (see ``TRANSFORMATIONS``).
    * SecLang variables, mapped onto caddy-waf targets (see ``VARIABLES``).
    * Severity → score (CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2) and the
      paranoia level from the ``paranoia-level/N`` tag.

What is skipped (each one is listed in the coverage report with its reason)
    * chained rules, negated operators, every non-regex operator
      (``@detectSQLi``, ``@eq``, ``@validateByteRange``, …),
    * rules whose only variables have no caddy-waf equivalent (``TX``,
      ``MATCHED_VAR``, ``&ARGS`` counts, ``FILES_TMP_CONTENT``, …),
    * rules that need a transformation which changes the value's meaning
      (``length``, ``base64Decode``, ``sha1``, …),
    * patterns that Go's RE2 rejects, and patterns containing ``%{...}``
      macros.

Every emitted rule uses ``"action": "log"`` by default: since v0.4.14 a log
rule's score is advisory and never blocks on its own. Add ``log_scores_block``
(and ``anomaly_threshold 5``) to a Caddyfile to get CRS-style anomaly-score
blocking, or pass ``--block-severity CRITICAL`` to emit block rules.

Usage
    python3 get_owasp_rules.py --ref v4.9.0 --output-dir rules/crs
    python3 get_owasp_rules.py --source /path/to/coreruleset/rules \\
        --paranoia-level 2 --output crs-pl2.json --report crs-pl2-coverage.md

Request-phase rules (phases 1-2) and response-phase rules (phases 3-4, the
CRS 95x data-leakage and web-shell checks) are written to separate files,
``<name>.json`` and ``<name>-response.json``, because response rules run
against every response body and are the more expensive half.

Validation uses Go: the script runs ``go run ./tools/re2check`` from the
repository root so every pattern is compiled by the same regexp package
caddy-waf uses. Pass ``--re2check python`` on a machine without Go to fall
back to a syntax heuristic that rejects lookaround and backreferences only.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

CRS_REPO = "coreruleset/coreruleset"
DEFAULT_REF = "v4.9.0"

SEVERITY_SCORE = {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}
SEVERITY_ORDER = ["NOTICE", "WARNING", "ERROR", "CRITICAL"]

# Operators this engine can express as a regex. Everything else is skipped.
REGEX_OPERATORS = {"rx", "pm", "pmFromFile", "pmf"}

# CRS variable -> caddy-waf target(s). ``None`` marks a variable the engine has
# no equivalent for; a rule whose positive variables all map to None is skipped.
# ARGS in ModSecurity covers query and body parameters, while caddy-waf's ARGS
# is the raw query string, so ARGS fans out to ARGS + BODY (raw body). XML is
# not parsed either: the raw body is the closest available value.
VARIABLES: Dict[str, Optional[Tuple[str, ...]]] = {
    "ARGS": ("ARGS", "BODY"),
    "ARGS_NAMES": ("ARGS", "BODY"),
    "ARGS_GET": ("ARGS",),
    "ARGS_GET_NAMES": ("ARGS",),
    "ARGS_POST": ("BODY",),
    "ARGS_POST_NAMES": ("BODY",),
    "ARGS_COMBINED_SIZE": None,
    "REQUEST_BODY": ("BODY",),
    "XML": ("BODY",),
    "REQUEST_COOKIES": ("COOKIES",),
    "REQUEST_COOKIES_NAMES": ("COOKIES",),
    "REQUEST_HEADERS": ("HEADERS",),
    "REQUEST_HEADERS_NAMES": ("HEADERS",),
    "REQUEST_FILENAME": ("PATH",),
    "REQUEST_BASENAME": ("PATH",),
    "REQUEST_URI": ("URI",),
    "REQUEST_URI_RAW": ("URI",),
    "REQUEST_LINE": ("URI",),
    "QUERY_STRING": ("ARGS",),
    "REQUEST_METHOD": ("METHOD",),
    "REQUEST_PROTOCOL": ("PROTOCOL",),
    "FILES": ("FILE_NAME",),
    "FILES_NAMES": ("FILE_NAME",),
    "FILES_TMPNAMES": None,
    "FILES_TMP_CONTENT": None,
    "FILES_COMBINED_SIZE": None,
    "FILES_SIZES": None,
    "RESPONSE_BODY": ("RESPONSE_BODY",),
    "RESPONSE_HEADERS": ("RESPONSE_HEADERS",),
    "RESPONSE_STATUS": None,
    "RESPONSE_CONTENT_TYPE": ("RESPONSE_HEADERS:Content-Type",),
    "REMOTE_ADDR": ("REMOTE_IP",),
    "TX": None,
    "MATCHED_VAR": None,
    "MATCHED_VARS": None,
    "MATCHED_VAR_NAME": None,
    "MATCHED_VARS_NAMES": None,
    "REQBODY_PROCESSOR": None,
    "REQBODY_ERROR": None,
    "REQBODY_PROCESSOR_ERROR": None,
    "MULTIPART_STRICT_ERROR": None,
    "MULTIPART_UNMATCHED_BOUNDARY": None,
    "MULTIPART_PART_HEADERS": None,
    "MULTIPART_FILENAME": None,
    "MULTIPART_NAME": None,
    "REQUEST_HEADERS_COUNT": None,
    "ENV": None,
    "GEO": None,
    "IP": None,
    "GLOBAL": None,
    "SESSION": None,
    "RESOURCE": None,
    "USER": None,
    "DURATION": None,
    "UNIQUE_ID": None,
    "SERVER_NAME": None,
    "SERVER_ADDR": None,
    "SERVER_PORT": None,
    "REMOTE_HOST": None,
    "REMOTE_PORT": None,
    "REMOTE_USER": None,
    "AUTH_TYPE": None,
    "FULL_REQUEST": None,
    "FULL_REQUEST_LENGTH": None,
    "PATH_INFO": None,
    "REQUEST_BODY_LENGTH": None,
    "INBOUND_DATA_ERROR": None,
    "OUTBOUND_DATA_ERROR": None,
    "STREAM_INPUT_BODY": None,
    "STREAM_OUTPUT_BODY": None,
    "WEBSERVER_ERROR_LOG": None,
    "XML_ERROR": None,
}

# Variables whose selector (``NAME:selector``) becomes a dynamic caddy-waf
# target. A regex selector (``/.../``) cannot be expressed and falls back to the
# whole collection.
SELECTOR_TARGETS = {
    "REQUEST_HEADERS": "HEADERS",
    "REQUEST_COOKIES": "COOKIES",
    "RESPONSE_HEADERS": "RESPONSE_HEADERS",
    "ARGS": "URL_PARAM",
    "ARGS_GET": "URL_PARAM",
}

# Transformations the engine implements (canonical spelling), listed in
# transform.go. ``urlDecode`` and ``urlDecodeUni`` are both accepted there.
ENGINE_TRANSFORMS = {
    "urldecode": "urlDecode",
    "urldecodeuni": "urlDecodeUni",
    "lowercase": "lowercase",
    "removenulls": "removeNulls",
    "compresswhitespace": "compressWhitespace",
    "replacecomments": "replaceComments",
    "htmlentitydecode": "htmlEntityDecode",
}

# CRS transformations with no engine implementation. ``approx`` maps to the
# nearest engine transformation; ``drop`` removes the step, which only loses
# evasion coverage (the raw value is always matched too); ``skip`` means the
# transformation changes the value's meaning, so the rule cannot be ported.
TRANSFORMATIONS = {
    "removewhitespace": ("approx", "compressWhitespace"),
    "removecomments": ("approx", "replaceComments"),
    "removecommentschar": ("approx", "replaceComments"),
    "utf8tounicode": ("drop", None),
    "normalisepath": ("drop", None),
    "normalizepath": ("drop", None),
    "normalisepathwin": ("drop", None),
    "normalizepathwin": ("drop", None),
    "cmdline": ("drop", None),
    "jsdecode": ("drop", None),
    "cssdecode": ("drop", None),
    "escapeseqdecode": ("drop", None),
    "trim": ("drop", None),
    "trimleft": ("drop", None),
    "trimright": ("drop", None),
    "length": ("skip", None),
    "base64decode": ("skip", None),
    "base64decodeext": ("skip", None),
    "base64encode": ("skip", None),
    "hexdecode": ("skip", None),
    "hexencode": ("skip", None),
    "sha1": ("skip", None),
    "md5": ("skip", None),
    "urlencode": ("skip", None),
    "sqlhexdecode": ("skip", None),
    "parityeven7bit": ("skip", None),
    "parityodd7bit": ("skip", None),
    "parityzero7bit": ("skip", None),
    "uppercase": ("skip", None),
}

# caddy-waf targets whose raw value is not URL-decoded by Go, so the CRS
# pattern (written against ModSecurity's decoded ARGS) needs a decode first.
RAW_TARGETS = {"ARGS", "BODY", "URI"}

# Targets that hold a whole collection in one string: the raw query string
# (``a=1&b=2``), the raw body, all headers joined as ``Name: value; Name: value``
# and all cookies joined as ``name=value; name=value``. ModSecurity applies a
# CRS pattern to each member value on its own, so ``^``/``$`` mean "start/end of
# the value"; against the joined string they would mean "start/end of the
# whole request part" and the rule could only match the first/last member.
# The translator therefore relaxes a leading ``^`` to "start or just after a
# member delimiter" and a trailing ``$`` to "end or just before one".
COLLECTION_TARGETS = {"ARGS", "BODY", "HEADERS", "COOKIES"}
RELAXED_START = r'(?:^|[&="]|:\s*)'
RELAXED_END = r'(?:$|[&;"])'
LEADING_FLAGS = re.compile(r"^\(\?[a-zA-Z]+\)")

# PCRE-only syntax RE2 rejects. Used by the Python fallback validator only.
PCRE_ONLY = re.compile(r"\(\?[=!<]|\(\?<[=!]|\(\?>|(?<!\\)\\[1-9]|\\[kK]<|(?<!\\)\\[GRhHKXZ]|(?<!\\)[+*?}]\+")


class SecLangError(ValueError):
    """Raised for a directive the parser cannot make sense of."""


@dataclass
class Variable:
    name: str
    selector: Optional[str] = None
    negated: bool = False
    counted: bool = False


@dataclass
class SecRule:
    file: str
    line: int
    variables: List[Variable]
    operator: str  # e.g. "rx"; "" for an implicit @rx
    argument: str
    negated: bool
    actions: List[Tuple[str, str]]  # (key, value); value "" for bare actions
    children: List["SecRule"] = field(default_factory=list)

    def action_values(self, key: str) -> List[str]:
        return [v for k, v in self.actions if k == key]

    def first_action(self, key: str) -> Optional[str]:
        for k, v in self.actions:
            if k == key:
                return v
        return None

    def has_action(self, key: str) -> bool:
        return any(k == key for k, _ in self.actions)

    @property
    def id(self) -> Optional[str]:
        return self.first_action("id")

    @property
    def paranoia_level(self) -> int:
        for tag in self.action_values("tag"):
            m = re.fullmatch(r"paranoia-level/(\d)", tag)
            if m:
                return int(m.group(1))
        return 1


@dataclass
class Translated:
    rule: OrderedDict
    paranoia_level: int
    notes: List[str]
    source_file: str


@dataclass
class Skipped:
    id: str
    source_file: str
    category: str
    detail: str = ""

    @property
    def reason(self) -> str:
        return f"{self.category}: {self.detail}" if self.detail else self.category


# --------------------------------------------------------------------------- #
# SecLang parsing
# --------------------------------------------------------------------------- #

def join_continuations(text: str) -> List[Tuple[int, str]]:
    """Return (first_line_number, logical_line) pairs with ``\\``-continuations joined."""
    out: List[Tuple[int, str]] = []
    buf: List[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = number
        if line.endswith("\\"):
            buf.append(line[:-1].rstrip() if buf else line[:-1])
            continue
        buf.append(line.lstrip() if buf else line)
        out.append((start, " ".join(buf) if len(buf) > 1 else buf[0]))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def tokenize_directive(line: str) -> List[str]:
    """Split a directive into whitespace-separated tokens honouring ``"…"`` quoting.

    Inside a quoted token ``\\"`` is an escaped quote; every other backslash is
    kept verbatim because it belongs to the regex.
    """
    tokens: List[str] = []
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        if line[i] == '"':
            j = i + 1
            buf: List[str] = []
            while j < n and line[j] != '"':
                if line[j] == "\\" and j + 1 < n:
                    if line[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    buf.append(line[j])
                    buf.append(line[j + 1])
                    j += 2
                    continue
                buf.append(line[j])
                j += 1
            if j >= n:
                raise SecLangError("unterminated quoted string")
            tokens.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            tokens.append(line[i:j])
            i = j
    return tokens


def split_actions(text: str) -> List[Tuple[str, str]]:
    """Split ``id:1,msg:'a, b',t:none`` into (key, value) pairs."""
    parts: List[str] = []
    buf: List[str] = []
    in_quote = False
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and in_quote:
            buf.append(text[i + 1])
            i += 2
            continue
        if c == "'":
            in_quote = not in_quote
        elif c == "," and not in_quote:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))

    actions: List[Tuple[str, str]] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
            value = value[1:-1]
        actions.append((key.strip(), value if sep else ""))
    return actions


def parse_variables(text: str) -> List[Variable]:
    variables: List[Variable] = []
    for item in text.split("|"):
        item = item.strip()
        if not item:
            continue
        negated = counted = False
        if item[0] == "!":
            negated = True
            item = item[1:]
        elif item[0] == "&":
            counted = True
            item = item[1:]
        name, _, selector = item.partition(":")
        selector = selector.strip() or None
        if selector and len(selector) >= 2 and selector[0] == "'" and selector[-1] == "'":
            selector = selector[1:-1]
        variables.append(Variable(name.strip().upper(), selector, negated, counted))
    return variables


def parse_operator(text: str) -> Tuple[str, str, bool]:
    """Return (operator, argument, negated) for a SecLang operator string."""
    text = text.strip()
    negated = False
    if text.startswith("!"):
        negated = True
        text = text[1:].lstrip()
    m = re.match(r"@(\w+)\s*(.*)", text, re.DOTALL)
    if m:
        return m.group(1), m.group(2), negated
    return "", text, negated  # implicit @rx


def parse_seclang(text: str, source_file: str) -> List[SecRule]:
    """Parse the SecRule directives in a .conf file, grouping chained rules."""
    rules: List[SecRule] = []
    pending_chain: Optional[SecRule] = None  # the rule whose ``chain`` is still open
    for number, line in join_continuations(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            tokens = tokenize_directive(stripped)
        except SecLangError as exc:
            raise SecLangError(f"{source_file}:{number}: {exc}") from exc
        if not tokens or tokens[0] != "SecRule":
            # SecAction, SecMarker, SecRuleEngine, SecComponentSignature, …
            # carry no detection logic this engine can use.
            continue
        if len(tokens) < 3:
            raise SecLangError(f"{source_file}:{number}: SecRule needs variables and an operator")
        operator, argument, negated = parse_operator(tokens[2])
        actions = split_actions(tokens[3]) if len(tokens) > 3 else []
        rule = SecRule(
            file=source_file,
            line=number,
            variables=parse_variables(tokens[1]),
            operator=operator,
            argument=argument,
            negated=negated,
            actions=actions,
        )
        if pending_chain is not None:
            root = pending_chain
            root.children.append(rule)
            pending_chain = root if rule.has_action("chain") else None
            continue
        rules.append(rule)
        if rule.has_action("chain"):
            pending_chain = rule
    return rules


# --------------------------------------------------------------------------- #
# Translation
# --------------------------------------------------------------------------- #

def load_data_file(path: str) -> List[str]:
    phrases: List[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            phrases.append(line)
    return phrases


def phrases_to_pattern(phrases: Iterable[str]) -> str:
    """Turn a ``@pm`` phrase list into a case-insensitive RE2 alternation.

    ``re.escape`` only escapes characters with regex meaning, and RE2 accepts a
    backslash before any ASCII punctuation, so its output is valid RE2.

    The phrases are sorted alphabetically on purpose: Go's regexp parser only
    factors common prefixes out of *adjacent* alternatives, and that factoring
    is what keeps a multi-thousand-entry list matchable. Emitting the same list
    ordered by length was measured at 10-20x slower per request.
    """
    unique = sorted(set(phrases))
    return "(?i)(?:" + "|".join(re.escape(p) for p in unique) + ")"


def map_targets(variables: List[Variable]) -> Tuple[List[str], List[str], List[str]]:
    """Return (targets, dropped_variable_descriptions, notes)."""
    targets: List[str] = []
    dropped: List[str] = []
    notes: List[str] = []

    def add(t: str) -> None:
        if t not in targets:
            targets.append(t)

    for var in variables:
        label = ("!" if var.negated else "&" if var.counted else "") + var.name + (
            ":" + var.selector if var.selector else ""
        )
        if var.negated:
            notes.append(f"exclusion {label} dropped (no per-value exclusions)")
            continue
        if var.counted:
            dropped.append(label)
            continue
        if var.name not in VARIABLES:
            dropped.append(label)
            continue
        mapping = VARIABLES[var.name]
        if mapping is None:
            dropped.append(label)
            continue
        if var.selector:
            if var.name == "REQUEST_HEADERS" and var.selector.lower() == "host":
                # Go's net/http moves the Host header to r.Host; the HEADERS:Host
                # target would always be empty (and skip the rule).
                add("HOST")
                continue
            base = SELECTOR_TARGETS.get(var.name)
            is_regex = var.selector.startswith("/") and var.selector.endswith("/")
            if base and not is_regex:
                add(f"{base}:{var.selector}")
                continue
            # Regex selectors and selectors on collections without a dynamic
            # target widen to the whole collection.
            notes.append(f"{label} widened to {'/'.join(mapping)}")
        for t in mapping:
            add(t)
    return targets, dropped, notes


def map_transformations(names: List[str]) -> Tuple[Optional[List[str]], List[str], Optional[str]]:
    """Return (chain, notes, unsupported_name).

    ``unsupported_name`` is set when a step changes the value's meaning and the
    rule must be skipped.
    """
    chain: List[str] = []
    notes: List[str] = []
    for raw in names:
        key = raw.strip().lower()
        if key == "none":
            chain = []
            continue
        if key in ENGINE_TRANSFORMS:
            chain.append(ENGINE_TRANSFORMS[key])
            continue
        kind, replacement = TRANSFORMATIONS.get(key, ("skip", None))
        if kind == "approx":
            chain.append(replacement)
            notes.append(f"t:{raw} approximated by {replacement}")
        elif kind == "drop":
            notes.append(f"t:{raw} dropped (not implemented)")
        else:
            return None, notes, raw
    deduped: List[str] = []
    for step in chain:
        if not deduped or deduped[-1] != step:
            deduped.append(step)
    return deduped, notes, None


def relax_anchors(pattern: str, targets: List[str]) -> Tuple[str, Optional[str]]:
    """Rewrite a leading ``^`` / trailing ``$`` for collection targets (see COLLECTION_TARGETS)."""
    if not any(t in COLLECTION_TARGETS for t in targets):
        return pattern, None
    flags = ""
    m = LEADING_FLAGS.match(pattern)
    if m:
        flags, pattern = m.group(0), pattern[m.end():]
    changed = []
    if pattern.startswith("^"):
        pattern = RELAXED_START + pattern[1:]
        changed.append("^")
    if pattern.endswith("$") and not pattern.endswith("\\$") and not pattern.endswith("[$"):
        pattern = pattern[:-1] + RELAXED_END
        changed.append("$")
    if not changed:
        return flags + pattern, None
    return flags + pattern, "anchor " + " and ".join(changed) + " relaxed to member boundaries (collection targets)"


def python_heuristic_failures(entries: List[Tuple[str, str]]) -> Dict[str, str]:
    """Best-effort stand-in for RE2 when Go is unavailable (lookaround, backrefs, \\R …)."""
    failures: Dict[str, str] = {}
    for rule_id, pattern in entries:
        m = PCRE_ONLY.search(pattern)
        if m:
            failures[rule_id] = f"PCRE-only construct {m.group(0)!r} (Python heuristic)"
    return failures


def re2_validate(entries: List[Tuple[str, str]], mode: str, repo_root: str) -> Dict[str, str]:
    """Return {id: error} for the patterns RE2 rejects."""
    failures: Dict[str, str] = {}
    if not entries:
        return failures
    if mode == "python":
        return python_heuristic_failures(entries)
    remaining = [{"id": i, "pattern": p} for i, p in entries]

    def fallback(problem: str) -> Dict[str, str]:
        # ``auto`` degrades to the heuristic (e.g. the script was copied out of
        # the repository, or Go is not installed); ``go`` is a hard requirement.
        if mode == "go":
            raise SystemExit(f"re2check: {problem}; pass --re2check python to skip RE2 validation")
        print(f"warning: {problem}; falling back to the Python syntax heuristic (patterns are NOT RE2-validated)",
              file=sys.stderr)
        return python_heuristic_failures(entries)

    helper = os.path.join(repo_root, "tools", "re2check", "main.go")
    if not os.path.isfile(helper):
        return fallback(f"{helper} not found")
    try:
        proc = subprocess.run(
            ["go", "run", "./tools/re2check"],
            input=json.dumps(remaining).encode("utf-8"),
            capture_output=True,
            cwd=repo_root,
            check=False,
        )
    except FileNotFoundError:
        return fallback("the go toolchain is not installed")
    if proc.returncode != 0:
        return fallback("go run ./tools/re2check failed: " + proc.stderr.decode("utf-8", "replace").strip())
    failures.update(json.loads(proc.stdout.decode("utf-8")))
    return failures


def translate_rule(rule: SecRule, data_dir: str) -> Tuple[Optional[Translated], Optional[Skipped]]:
    rule_id = rule.id
    source = os.path.basename(rule.file)
    if rule_id is None:
        return None, None  # anonymous rules carry no detection logic
    skip = lambda category, detail="": (None, Skipped(rule_id, source, category, detail))  # noqa: E731

    if rule.children:
        return skip("chained rule", "caddy-waf has no rule chaining")
    severity = (rule.first_action("severity") or "").upper()
    if rule.has_action("skipAfter") or not severity:
        return skip("control/flow rule", "no severity")
    if rule.negated:
        return skip("negated operator", f"!@{rule.operator or 'rx'}")
    operator = rule.operator or "rx"
    if operator not in REGEX_OPERATORS:
        return skip("non-regex operator", f"@{operator}")

    if operator == "rx":
        pattern = rule.argument
        if "%{" in pattern:
            return skip("macro expansion", "pattern uses %{…}")
        if re.fullmatch(r"\^\s*\$", pattern):
            # caddy-waf skips a rule when the target is missing or empty, so an
            # "is empty" presence check can never fire (see dead_rules_test.go).
            return skip("presence check", "^$ never evaluated: empty targets skip the rule")
    elif operator == "pm":
        pattern = phrases_to_pattern(rule.argument.split())
    else:
        path = os.path.join(data_dir, rule.argument.strip())
        if not os.path.isfile(path):
            return skip("data file not found", rule.argument.strip())
        pattern = phrases_to_pattern(load_data_file(path))
    if not pattern:
        return skip("empty pattern")

    targets, dropped_vars, notes = map_targets(rule.variables)
    if not targets:
        return skip("no mappable target", "|".join(dropped_vars or ["(none)"]))
    for label in dropped_vars:
        notes.append(f"variable {label} dropped (no caddy-waf equivalent)")
    if operator == "rx":
        pattern, anchor_note = relax_anchors(pattern, targets)
        if anchor_note:
            notes.append(anchor_note)

    chain, t_notes, unsupported = map_transformations(rule.action_values("t"))
    notes.extend(t_notes)
    if unsupported:
        return skip("unsupported transformation", f"t:{unsupported} changes the value's meaning")
    assert chain is not None
    if any(t in RAW_TARGETS for t in targets) and "urlDecodeUni" not in chain and "urlDecode" not in chain:
        # ModSecurity hands CRS an already-decoded ARGS; caddy-waf's ARGS/BODY/URI
        # are raw, so decode first to match the same text the rule was written for.
        chain.insert(0, "urlDecodeUni")

    score = SEVERITY_SCORE.get(severity)
    if score is None:
        return skip("unknown severity", severity)

    phase = int(rule.first_action("phase") or 2)
    if phase not in (1, 2, 3, 4):
        return skip("invalid phase", str(phase))
    if any(t.startswith("RESPONSE_") for t in targets) and phase < 3:
        phase = 4
        notes.append("phase moved to 4 (response targets)")

    msg = rule.first_action("msg") or "No description provided"
    pl = rule.paranoia_level
    out: "OrderedDict[str, object]" = OrderedDict()
    out["id"] = f"crs-{rule_id}"
    out["phase"] = phase
    out["pattern"] = pattern
    out["targets"] = targets
    out["severity"] = severity
    out["action"] = "log"
    out["score"] = score
    out["description"] = f"OWASP CRS {rule_id} PL{pl}: {msg}"
    out["transformations"] = chain
    return Translated(out, pl, notes, source), None


def translate_directory(
    rules_dir: str,
    re2_mode: str,
    repo_root: str,
    tuning: Optional[Tuning] = None,
) -> Tuple[List[Translated], List[Skipped], Counter]:
    tuning = tuning or Tuning()
    translated: List[Translated] = []
    skipped: List[Skipped] = []
    seen_ids: Dict[str, str] = {}
    totals: Counter = Counter()
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith(".conf"):
            continue
        path = os.path.join(rules_dir, name)
        with open(path, encoding="utf-8", errors="replace") as fh:
            rules = parse_seclang(fh.read(), path)
        for rule in rules:
            if rule.id is None:
                continue
            totals[name] += 1
            if rule.id in tuning.remove:
                skipped.append(Skipped(rule.id, name, "removed by tuning", tuning.remove[rule.id]))
                continue
            if rule.id in seen_ids:
                skipped.append(Skipped(rule.id, name, "duplicate id", f"already defined in {seen_ids[rule.id]}"))
                continue
            seen_ids[rule.id] = name
            result, skip = translate_rule(rule, rules_dir)
            if result and rule.id in tuning.remove_targets:
                for target, reason in tuning.remove_targets[rule.id].items():
                    if target in result.rule["targets"]:
                        result.rule["targets"].remove(target)
                        result.notes.append(f"target {target} removed by tuning: {reason}")
                if not result.rule["targets"]:
                    skip, result = Skipped(rule.id, name, "removed by tuning", "every target removed"), None
            if skip:
                skipped.append(skip)
            elif result:
                translated.append(result)

    failures = re2_validate([(t.rule["id"], t.rule["pattern"]) for t in translated], re2_mode, repo_root)
    if failures:
        kept: List[Translated] = []
        for t in translated:
            err = failures.get(t.rule["id"])
            if err is None:
                kept.append(t)
            else:
                skipped.append(Skipped(t.rule["id"][len("crs-"):], t.source_file, "RE2 rejects the pattern", err))
        translated = kept
    skipped.sort(key=lambda s: (s.source_file, s.id))
    return translated, skipped, totals


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def apply_block_severity(translated: List[Translated], block_severity: Optional[str]) -> None:
    if not block_severity:
        return
    threshold = SEVERITY_ORDER.index(block_severity.upper())
    for t in translated:
        if SEVERITY_ORDER.index(t.rule["severity"]) >= threshold:
            t.rule["action"] = "block"


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def is_request_phase(phase: int) -> bool:
    return phase in (1, 2)


def is_response_phase(phase: int) -> bool:
    return phase in (3, 4)


def write_bundle(path: str, rules: List[OrderedDict]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rules, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def write_report(
    path: str,
    ref: str,
    translated: List[Translated],
    skipped: List[Skipped],
    totals: Counter,
    outputs: Dict[str, int],
    tuning_path: Optional[str] = None,
) -> None:
    by_file_emitted: Counter = Counter(t.source_file for t in translated)
    by_file_skipped: Counter = Counter(s.source_file for s in skipped)
    reasons: Counter = Counter(s.category for s in skipped)
    by_pl: Counter = Counter(t.paranoia_level for t in translated)

    lines: List[str] = []
    lines.append(f"# OWASP CRS {ref} translation coverage")
    lines.append("")
    lines.append(
        "Generated by `get_owasp_rules.py`. caddy-waf ports the `@rx`/`@pm` subset of "
        "the Core Rule Set that fits its one-regex-per-target model; this report "
        "lists what was ported, what was skipped and why, and which ported rules "
        "lost a transformation or an exclusion on the way. **This is CRS-informed "
        "coverage, not CRS parity.**"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    total_rules = sum(totals.values())
    lines.append(f"- CRS rules with an id: {total_rules}")
    lines.append(f"- Ported: {len(translated)} (" + ", ".join(f"PL{pl}: {n}" for pl, n in sorted(by_pl.items())) + ")")
    lines.append(f"- Skipped: {len(skipped)}")
    for name, count in outputs.items():
        lines.append(f"- `{os.path.basename(name)}`: {plural(count, 'rule')}")
    lines.append("")
    lines.append("### Skip reasons")
    lines.append("")
    lines.append("| Reason | Rules |")
    lines.append("|---|---:|")
    for reason, count in reasons.most_common():
        lines.append(f"| {reason} | {count} |")
    lines.append("")
    lines.append("### Per file")
    lines.append("")
    lines.append("| CRS file | Rules | Ported | Skipped |")
    lines.append("|---|---:|---:|---:|")
    for name in sorted(totals):
        lines.append(f"| {name} | {totals[name]} | {by_file_emitted[name]} | {by_file_skipped[name]} |")
    lines.append("")
    lines.append("## What the port cannot express")
    lines.append("")
    lines.append(
        "- **Chained rules.** A `chain` narrows a match with a second condition "
        "(a count, a transaction variable, a second regex). caddy-waf evaluates "
        "each rule independently, so chained rules are skipped rather than "
        "ported without their narrowing condition."
    )
    lines.append(
        "- **Non-regex operators.** `@detectSQLi`/`@detectXSS` (libinjection), "
        "`@validateByteRange`, `@validateUrlEncoding`, `@eq`/`@lt`/`@ge`, "
        "`@ipMatch`, `@streq`, `@within` and `@endsWith` have no regex "
        "equivalent."
    )
    lines.append(
        "- **Structured request parsing.** ModSecurity matches `ARGS` against each "
        "decoded parameter value and `XML:/*` against parsed XML nodes; caddy-waf "
        "matches the raw query string and raw body, so a pattern can also see "
        "parameter names, JSON syntax and multipart framing. `ARGS` is emitted as "
        "`ARGS` + `BODY`; `XML` as `BODY`."
    )
    lines.append(
        "- **Exclusions and counts.** `!REQUEST_COOKIES:/__utm/`-style exclusions "
        "and `&ARGS` counts are dropped; the rule still applies to the whole "
        "collection."
    )
    lines.append(
        "- **Transformations.** `cmdLine`, `normalizePath`, `jsDecode`, "
        "`cssDecode`, `utf8toUnicode` and `escapeSeqDecode` are not implemented "
        "and are dropped (the raw value is still matched, so this only loses "
        "evasion coverage). `removeWhitespace` and `removeComments` are "
        "approximated by `compressWhitespace` and `replaceComments`. Rules that "
        "need `length`, `base64Decode`, `hexDecode`, `sha1` or `urlEncode` "
        "are skipped because those change what the pattern is matched against."
    )
    lines.append(
        "- **Anchors.** ModSecurity matches each parameter, header and cookie "
        "value on its own; caddy-waf matches the raw query string, raw body, "
        "and the joined header/cookie lists. A leading `^` or trailing `$` in a "
        "rule on those targets is rewritten to a member boundary "
        "(`(?:^|[&=\"]|:\\s*)` / `(?:$|[&;\"])`) so the rule can still match a "
        "value that is not the first or last one. Affected rules are listed "
        "below."
    )
    tuning_source = f"`{os.path.basename(tuning_path)}` (passed with `--tuning`)" if tuning_path else "a `--tuning` file"
    lines.append(
        f"- **Tuning.** {tuning_source} can remove a rule, or remove one target "
        "from a rule that cannot be applied to a raw body without matching "
        "ordinary JSON, YAML or multipart framing; the reason is recorded per "
        "rule below. This is the caddy-waf equivalent of the CRS "
        "`SecRuleRemoveById` / `SecRuleUpdateTargetById` exclusions."
    )
    lines.append(
        "- **Paranoia levels and scoring.** The `paranoia-level/N` tag is recorded "
        "in each rule's description and used to split the output files; there "
        "is no runtime paranoia-level switch. Scores follow CRS severities "
        "(CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2). Every rule is `log`, "
        "which is advisory unless `log_scores_block` is set."
    )
    lines.append("")
    lines.append("## Ported rules with a lossy translation")
    lines.append("")
    lossy = [t for t in translated if t.notes]
    if lossy:
        lines.append("| Rule | File | Notes |")
        lines.append("|---|---|---|")
        for t in lossy:
            lines.append(f"| {t.rule['id']} | {t.source_file} | {'; '.join(t.notes)} |")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Skipped rules")
    lines.append("")
    lines.append("| CRS id | File | Reason |")
    lines.append("|---|---|---|")
    for s in skipped:
        reason = s.reason.replace("|", "\\|")
        lines.append(f"| {s.id} | {s.source_file} | {reason} |")
    lines.append("")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------- #
# Source acquisition
# --------------------------------------------------------------------------- #

def download_crs(ref: str, dest: str) -> str:
    """Download the CRS tarball for ``ref`` and return the extracted rules dir."""
    url = f"https://github.com/{CRS_REPO}/archive/refs/tags/{ref}.tar.gz"
    print(f"Downloading {url}")
    with urllib.request.urlopen(url) as resp:  # noqa: S310 - fixed GitHub URL
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = [m for m in tar.getmembers() if "/rules/" in m.name and m.isfile()]
        if not members:
            raise SystemExit("archive contains no rules/ directory")
        for m in members:
            # Flatten to dest/rules/<name>; the archive root is coreruleset-<ver>/.
            m.name = "rules/" + m.name.split("/rules/", 1)[1]
            if ".." in m.name.split("/"):
                continue
            tar.extract(m, dest)
    return os.path.join(dest, "rules")


@dataclass
class Tuning:
    """Per-rule adjustments, the caddy-waf equivalent of CRS ``SecRuleRemoveById``
    and ``SecRuleUpdateTargetById`` exclusions."""
    remove: Dict[str, str] = field(default_factory=dict)  # id -> reason
    remove_targets: Dict[str, Dict[str, str]] = field(default_factory=dict)  # id -> {target: reason}


def read_tuning(path: Optional[str], inline_exclude: Optional[str]) -> Tuning:
    """Parse a tuning file.

    One directive per line, ``#`` starts a comment (the comment is kept as the
    reason in the coverage report)::

        942190 remove-target BODY   # quote-prefixed keyword branch matches JSON keys
        920350 remove               # Host is an IP on purpose in this deployment
    """
    tuning = Tuning()
    if inline_exclude:
        for rule_id in inline_exclude.split(","):
            if rule_id.strip():
                tuning.remove[rule_id.strip()] = "listed in --exclude"
    if not path:
        return tuning
    with open(path, encoding="utf-8") as fh:
        for number, raw in enumerate(fh, 1):
            text, _, comment = raw.partition("#")
            words = text.split()
            if not words:
                continue
            reason = comment.strip() or f"{os.path.basename(path)}:{number}"
            rule_id = words[0]
            directive = words[1] if len(words) > 1 else "remove"
            if directive == "remove" and len(words) <= 2:
                tuning.remove[rule_id] = reason
            elif directive == "remove-target" and len(words) == 3:
                for target in words[2].split(","):
                    tuning.remove_targets.setdefault(rule_id, {})[target.strip().upper()] = reason
            else:
                raise SystemExit(f"{path}:{number}: expected '<id> remove' or '<id> remove-target <TARGET[,TARGET]>'")
    return tuning


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", help="local CRS rules/ directory (skips the download; --ref then only labels the report)")
    parser.add_argument("--ref", default=DEFAULT_REF, help=f"CRS git tag to download (default {DEFAULT_REF})")
    out = parser.add_mutually_exclusive_group()
    out.add_argument("--output-dir", help="write one request bundle per paranoia level (crs-pl1.json … crs-pl4.json) "
                     "plus the response-phase rules as crs-plN-response.json")
    out.add_argument("--output", help="write one cumulative request bundle up to --paranoia-level; the response-phase "
                     "rules go to <name>-response.json next to it")
    parser.add_argument("--paranoia-level", type=int, default=1, choices=[1, 2, 3, 4],
                        help="highest paranoia level to include in --output (default 1)")
    parser.add_argument("--report", help="coverage report path (default: COVERAGE.md next to the output)")
    parser.add_argument("--exclude", help="comma-separated CRS ids to leave out")
    parser.add_argument("--tuning", help="tuning file: '<id> remove' or '<id> remove-target <TARGET>' per line, # comments")
    parser.add_argument("--block-severity", choices=SEVERITY_ORDER,
                        help="emit action \"block\" for rules at or above this severity (default: all \"log\")")
    parser.add_argument("--re2check", choices=["auto", "go", "python"], default="auto",
                        help="pattern validator: go (require the Go helper), python (syntax heuristic only), auto")
    args = parser.parse_args(argv)

    if not args.output_dir and not args.output:
        args.output_dir = "rules/crs"
    repo_root = os.path.dirname(os.path.abspath(__file__))
    ref = args.ref

    with tempfile.TemporaryDirectory() as tmp:
        rules_dir = args.source or download_crs(args.ref, tmp)
        tuning = read_tuning(args.tuning, args.exclude)
        translated, skipped, totals = translate_directory(rules_dir, args.re2check, repo_root, tuning)

    apply_block_severity(translated, args.block_severity)
    translated.sort(key=lambda t: t.rule["id"])

    outputs: Dict[str, int] = {}
    if args.output_dir:
        for pl in (1, 2, 3, 4):
            selected = [t for t in translated if t.paranoia_level == pl]
            for suffix, phase_ok in (("", is_request_phase), ("-response", is_response_phase)):
                rules = [t.rule for t in selected if phase_ok(t.rule["phase"])]
                if not rules and suffix:
                    continue
                path = os.path.join(args.output_dir, f"crs-pl{pl}{suffix}.json")
                write_bundle(path, rules)
                outputs[path] = len(rules)
        report = args.report or os.path.join(args.output_dir, "COVERAGE.md")
    else:
        selected = [t for t in translated if t.paranoia_level <= args.paranoia_level]
        base, ext = os.path.splitext(args.output)
        for suffix, phase_ok in (("", is_request_phase), ("-response", is_response_phase)):
            rules = [t.rule for t in selected if phase_ok(t.rule["phase"])]
            if not rules and suffix:
                continue
            path = base + suffix + ext
            write_bundle(path, rules)
            outputs[path] = len(rules)
        report = args.report or os.path.join(os.path.dirname(args.output) or ".", "COVERAGE.md")

    write_report(report, ref, translated, skipped, totals, outputs, args.tuning)
    for name, count in outputs.items():
        print(f"wrote {plural(count, 'rule')} to {name}")
    print(f"ported {len(translated)} of {sum(totals.values())} CRS rules; {len(skipped)} skipped (see {report})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
