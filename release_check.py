#!/usr/bin/env python3
"""Conservative, local release auditing. Python 3.11+, Git, no runtime packages."""
from __future__ import annotations

import argparse
import ast
import base64
from collections import Counter
from datetime import datetime, timezone
import errno
import fnmatch
import gzip
import hashlib
import html
import io
import ipaddress
import inspect
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unicodedata
import zipfile
import zlib
from urllib.parse import urlsplit

VERSION = "0.1.0"
MAX_RECEIPT_BYTES = 1024 * 1024
ARCHIVE_MAX_BYTES, ARCHIVE_MAX_MEMBERS, ARCHIVE_MAX_DEPTH = 64 << 20, 10_000, 4
MEDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf", ".mp4", ".mov", ".wav", ".mp3", ".heic"}
GENERATED = {".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build"}
ROOT_LICENSE_FILES = ("LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING")
ROOT_LICENSES = ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC")
NOTICE_LICENSES = {"BSD-2-Clause", "BSD-3-Clause", "ISC"}
REQUIRED_DOCUMENTS = ("README.md", "CONTRIBUTING.md", "SECURITY.md")
README_HEADINGS = ("limitations", "known issues", "where it fails")
ISSUE_TEMPLATE_DIR = ".github/ISSUE_TEMPLATE"
ISSUE_TEMPLATE_GLOBS = ("*.y*ml", "*.md")
TEST_DIR, TEST_GLOB = "tests", "test*.py"
VERIFY_BACKENDS = ("host", "coldbox")
CHECK_ROLES = ("quickstart", "tests", "lint", "types", "build", "syntax")
CONFIGURED_CHECKS = (("ruff", "lint"), ("mypy", "types"))
DEPENDENCY_LICENSE_FILE = r"^(?:LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE).*"
MANIFEST_KEYS = ("exclude", "approvals", "quickstart", "checks", "license", "dependency_licenses", "verify_tools")
DEFAULT_EXCLUDES = [".git", ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "credentials*", "*token.json", ".close_idle_tabs_state.json"]
INCOMPLETE_KINDS = {
    "verification-not-run", "verification-not-configured", "verify-tool-missing",
    "venv-creation-failed", "quickstart-not-declared", "test-command-not-declared",
    "configured-check-not-declared", "dependency-metadata-failed",
    "dependency-ecosystem-manual-review", "dynamic-license-or-dependencies",
    "manual-review", "verify-backend-unavailable",
}
PATTERNS = {
    "email": r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}(?![\w.-])",
    "phone": r"(?<!\w)(?:(?:\+\d{1,3}[ .-])?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}|\+\d{8,15})(?!\w)",
    "home-path": r"(?:/home/[^/\s\"'<>]+|/Users/[^/\s\"'<>]+|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'<>]+)",
    "tailnet-host": r"\b[\w.-]+\.ts\.net\b",
    "internal-host": r"(?<![\w.-])(?:[\w-]+(?:\.[\w-]+)*\.(?:internal|local|lan|corp|home|localdomain)|(?!(?:utf|ucs|iso|cp|latin)-\d{2}(?![\w.-]))[a-z][a-z-]*-\d{2})(?![\w.-]|\()",
    "private-repo-url": r"(?:https?://|git@)(?:gitlab|github|git|gitea)\.(?:internal|local|lan|corp)[^\s\"'<>]*|https?://[^/\s]+/[^\s\"'<>]*\bprivate\b[^\s\"'<>]*",
}
SECRET_PATTERNS = {
    "private-key": r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    "github-token": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
    "aws-key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "api-key": r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{15,})\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "credential-url": r"(?:https?|postgres(?:ql)?|mysql|redis)://[^\s/:]+:[^\s/@]+@[^\s]+",
    "assigned-secret": r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[:=]\s*[\"']?([^\s\"',;\}\]]{8,})",
    "bearer": r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{16,})",
}

DEPLOYMENT_SECRET_KEY = r"(?i)passw(?:or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"


def literal_value(value: str, yaml: bool = True) -> bool:
    value = value.strip()
    quoted = re.match(r"\"([^\"]*)\"|'([^']*)'", value)
    if quoted:
        value = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
    elif yaml:
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if value.lower() in {"true", "false", "yes", "no", "null", "~"}:
            return False
    return bool(value) and not re.fullmatch(
        r"\$\{\{(?:(?!\}\}).)*\}\}|\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*(?::?\?[^}]*)?\})", value)


def flow_items(text: str) -> list[str]:
    items, depth, quote, start = [], 0, None, 0
    for index, char in enumerate(text):
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index])
            start = index + 1
    return [*items, text[start:]]


def flow_secret_data(text: str):
    stack, quote = [], None
    for index, char in enumerate(text):
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "{":
            stack.append(index)
        elif char == "}" and stack:
            start = stack.pop()
            pairs = [re.match(r"\s*[\"']?([\w-]+)[\"']?\s*:\s*(.*?)\s*$", item, re.S) for item in flow_items(text[start + 1:index])]
            pairs = {pair.group(1): pair.group(2) for pair in pairs if pair}
            if (pairs.get("kind", "").strip("\"'") == "Secret"
                    and any(re.sub(r"\s", "", pairs.get(key, "")) not in {"", "{}"} for key in ("data", "stringData"))):
                yield text.count("\n", 0, start) + 1


def kubernetes_secret_data(lines: list[str]):
    def column(line):
        return len(re.match(r"[ \t]*(?:-[ \t]+)?", line).group())

    def indent(line):
        return len(line) - len(line.lstrip())

    def skip(line):
        return not line.strip() or line.lstrip().startswith("#")

    for index, line in enumerate(lines):
        if not re.match(r"[ \t]*(?:-[ \t]+)?kind:\s*[\"']?Secret[\"']?\s*(?:#.*)?$", line):
            continue
        key = column(line)
        start = index
        while start > 0 and not (lines[start].lstrip().startswith("- ") and column(lines[start]) == key):
            previous = lines[start - 1]
            if previous.startswith(("---", "...")) or not skip(previous) and indent(previous) < key and column(previous) != key:
                break
            start -= 1
        end = index + 1
        while end < len(lines) and not lines[end].startswith(("---", "...")) and (skip(lines[end]) or indent(lines[end]) >= key):
            end += 1
        for number in range(start, end):
            data = re.match(r"[ \t]*(?:-[ \t]+)?(?:data|stringData):[ \t]*(.*)$", lines[number])
            if not data or column(lines[number]) != key:
                continue
            following = next((other for other in lines[number + 1:end] if not skip(other)), "")
            if re.sub(r"#.*", "", data.group(1)).strip() not in {"", "{}"} or indent(following) > key:
                yield number + 1


def yaml_block_lines(text: str, keys: set[str]):
    block = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if block is not None and indent > block:
            yield number, stripped
            continue
        block = None
        match = re.match(r"(?:-\s+)?([\w-]+):\s*(.*)$", stripped)
        if match and match.group(1) in keys:
            if match.group(2) and not match.group(2).startswith("#"):
                yield number, match.group(2)
            else:
                block = indent


class AuditError(Exception):
    """Errors use a generic code, never exception contents; detail may name keys and expected types only."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.detail = detail


def explain(reason: str) -> None:
    print(reason, file=sys.stderr)


def env_value(name: str) -> str | None:
    if os.environ.get("COLDRELEASE_" + name):
        return os.environ["COLDRELEASE_" + name]
    legacy = os.environ.get("RELEASE_CHECK_" + name)
    if legacy:
        explain(f"RELEASE_CHECK_{name} is deprecated; set COLDRELEASE_{name} instead")
    return legacy or None


def failure_cause(exc: BaseException) -> str:
    name = type(exc).__name__
    if isinstance(exc, OSError) and exc.errno in errno.errorcode:
        return f"{name} ({errno.errorcode[exc.errno]})"
    if isinstance(exc, subprocess.CalledProcessError) and isinstance(exc.cmd, list) and exc.cmd[:1] == ["git"]:
        words = iter(exc.cmd[1:])
        for word in words:
            if word in {"-C", "-c"}:
                next(words, None)
            elif not word.startswith("-"):
                if re.fullmatch(r"[a-z][a-z-]*", word):
                    return f"{name} (git {word} failed)"
                break
    return name


def positive_seconds(value: str) -> int:
    reason = "must be a whole number of seconds greater than 0"
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(reason) from None
    if seconds <= 0:
        raise argparse.ArgumentTypeError(reason)
    return seconds


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally includes the offending argument, which may be a secret.
        print('{"ready":false,"error":"invalid-arguments"}', file=sys.stderr)
        reason = "see --help"
        fixed_messages = {
            "repository path does not exist or is not a directory",
            "pass a repository or --requirements",
            "pass --denylist or set COLDRELEASE_DENYLIST",
            "--published-target requires --verify and cannot export or validate an old receipt",
        }
        if message in fixed_messages:
            reason = message
        elif message == "argument --timeout: must be a whole number of seconds greater than 0":
            reason = "--timeout must be a whole number of seconds greater than 0"
        elif message.startswith("unrecognized arguments:"):
            reason = "unknown option or extra argument; see --help"
        elif message.startswith("the following arguments are required: "):
            names = message.removeprefix("the following arguments are required: ").split(", ")
            missing = [action.dest for action in self._actions if action.dest in names]
            if missing and len(missing) == len(names):
                reason = "missing " + " and ".join(missing) + "; see --help"
        else:
            for action in self._get_positional_actions():
                if action.choices and message.startswith(f"argument {action.dest}: invalid choice:"):
                    reason = f"unknown {action.dest}; use one of: " + ", ".join(action.choices)
                    break
            for option in self._option_string_actions:
                if message == f"argument {option}: expected one argument":
                    reason = f"missing value for {option}"
                    break
        print(reason, file=sys.stderr)
        raise SystemExit(2)


def fingerprint(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogateescape")
    return hashlib.sha256(value).hexdigest()[:16]


def opaque_secret(value: str) -> bool:
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", value) or value.startswith("sha256:"):
        return False
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values()) if value else 0
    return entropy >= 4.3 and bool(re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value))


def npm_integrity_spans(text: str, path: str) -> list[tuple[int, int]]:
    if (Path(path).name not in {"package-lock.json", "npm-shrinkwrap.json"}
            or len(text) > MAX_METADATA_BYTES or "\ufffd" in text):
        return []
    def invalid_constant(value):
        raise ValueError("invalid-json-constant")
    try:
        document = json.loads(text, object_pairs_hook=unique_json_object,
                              parse_constant=invalid_constant)
        if (not isinstance(document, dict) or type(document.get("lockfileVersion")) is not int
                or document["lockfileVersion"] != 3 or not isinstance(document.get("packages"), dict)):
            return []
        packages = document["packages"]
        if any(not isinstance(entry, dict) for entry in packages.values()):
            return []
        owners = {id(entry) for entry in packages.values()}
        pending = [document]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if "integrity" in item and id(item) not in owners:
                    return []
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        sizes = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
        for entry in packages.values():
            if "integrity" not in entry:
                continue
            value = entry["integrity"]
            if not isinstance(value, str):
                return []
            match = re.fullmatch(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})", value)
            if not match:
                return []
            digest = base64.b64decode(match[2], validate=True)
            if len(digest) != sizes[match[1]] or base64.b64encode(digest).decode("ascii") != match[2]:
                return []
        return [match.span(1) for match in re.finditer(
            r'(?<!\\)"integrity"\s*:\s*"((?:sha1|sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2})"', text)]
    except (ValueError, RecursionError):
        return []


def placeholder_credential_url(value: str) -> bool:
    if re.search(r"[^\x21-\x7e]|[%\\'\"<>]", value):
        return False
    try:
        url = urlsplit(value)
        host = url.hostname or ""
        if (url.scheme not in {"http", "https"}
                or url.username not in {"user", "u", "username"}
                or url.password not in {"pass", "p", "password"}
                or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", host)):
            return False
        authority = f"{url.username}:{url.password}@{host}"
        if url.port is not None:
            if not 1 <= url.port <= 65535:
                return False
            authority += f":{url.port}"
        return url.netloc == authority and (
            host in {"example.com", "example.net", "example.org"}
            or host.endswith((".test", ".example", ".invalid")))
    except ValueError:
        return False


def python_expression_spans(text: str, path: str) -> dict[str, list[tuple[int, int]]]:
    spans = {"internal-host": [], "assigned-secret": [], "credential-url": []}
    if Path(path).suffix != ".py" or "\ufffd" in text:
        return spans
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return spans
    lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", text)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def position(row: int, column: int) -> int:
        # AST columns count UTF-8 bytes, while regex spans count characters.
        return offsets[row - 1] + len(lines[row - 1].encode("utf-8")[:column].decode("utf-8"))

    expected_prefixes = {
        id(node.args[0]) for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"
        and node.func.attr == "assertIn" and len(node.args) == 2 and not node.keywords
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            start = position(node.lineno, node.col_offset)
            end = position(node.end_lineno, node.end_col_offset)
            literal = text[start:end]
            if (len(literal) >= 2 and literal[0] in "\"'" and literal[-1] == literal[0]
                    and literal[1:-1] == node.value):
                if placeholder_credential_url(node.value):
                    spans["credential-url"].append((start + 1, end - 1))
                value = node.value.removeprefix("--password=")
                reference = re.fullmatch(r"secret://[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|\$\{AGENTLOCKER_SECRET_[A-Za-z0-9_]+\}|<your-password>", value)
                embedded_secret = any(re.search(pattern.replace(r"\b", ""), value)
                                      for kind, pattern in SECRET_PATTERNS.items()
                                      if kind in {"github-token", "aws-key", "api-key", "jwt"})
                embedded_secret |= any(opaque_secret(token) for token in re.findall(r"[A-Za-z0-9_+=-]{32,}", value))
                expected_prefix = id(node) in expected_prefixes and node.value in {
                    "--password=" + "secret://", "--password=" + "${AGENTLOCKER_SECRET_"}
                if reference and not embedded_secret or expected_prefix:
                    spans["assigned-secret"].append((start + 1, end - 1))
            continue
        expression = node
        root = expression
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name):
            continue
        start = position(expression.lineno, expression.col_offset)
        end = position(expression.end_lineno, expression.end_col_offset)
        kinds = ["assigned-secret"]
        if isinstance(node, ast.Attribute):
            kinds.append("internal-host")
        for line in text[start:end].splitlines(keepends=True):
            for kind in kinds:
                spans[kind].append((start, start + len(line.partition("#")[0])))
            start += len(line)

    return spans


def issue_template_locations() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return ((ISSUE_TEMPLATE_DIR, ISSUE_TEMPLATE_GLOBS), (".gitlab/issue_templates", ("*.md",)),
            (".gitea/ISSUE_TEMPLATE", ISSUE_TEMPLATE_GLOBS), (".gitea/issue_template", ISSUE_TEMPLATE_GLOBS))


def private_repo_ref(url: str) -> str:
    path = re.sub(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/]+/|[^@/\s]+@[^:/\s]+:)", "", url.strip())
    return path.rstrip("/").removesuffix(".git").rstrip("/") or url


def private_repo_url(value: str) -> bool:
    if value.lower().startswith("git@"):
        return True
    try:
        url = urlsplit(value)
    except ValueError:
        return True
    return bool(re.fullmatch(r"(?:gitlab|github|git|gitea)\.(?:internal|local|lan|corp)",
                             url.hostname or "", re.I)
                or re.search(r"\bprivate\b", url.path, re.I))


def multiline(pattern: str) -> str:
    return "(?m:" + pattern + ")"


def owner_patterns(obj) -> list[dict]:
    patterns = obj.get("patterns", []) if isinstance(obj, dict) else []
    shape = "denylist patterns must be a list of {kind, pattern} with a new lowercase kind and a regex whose every match is at least one character"
    kinds = set()
    for item in patterns if isinstance(patterns, list) else [None]:
        try:
            valid = (isinstance(item, dict) and set(item) == {"kind", "pattern"}
                     and isinstance(item["kind"], str) and re.fullmatch(r"[a-z][a-z0-9-]*", item["kind"])
                     and item["kind"] not in {*PATTERNS, *SECRET_PATTERNS, *INCOMPLETE_KINDS, "denylist", *kinds}
                     and isinstance(item["pattern"], str) and re.compile(multiline(item["pattern"]), re.I)
                     and re._parser.parse(multiline(item["pattern"]), re.I).getwidth()[0] > 0)
        except re.error:
            valid = False
        if not valid:
            explain(shape)
            raise AuditError("denylist-schema")
        kinds.add(item["kind"])
    return patterns


def load_terms(path: Path) -> list:
    """Accept JSON arrays, {terms: [...]}, category-based JSON, or newline lists.

    A JSON object may add owner detectors as "patterns"; they follow the text terms."""
    raw = path.read_text(encoding="utf-8")
    shape = "denylist must be a JSON list, {terms: [...]} or {categories: ...}"
    obj = None
    if path.suffix.lower() == ".json" or raw.lstrip().startswith(("[", "{")):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            explain("denylist file is not valid JSON" if raw.strip() else "denylist file is empty")
            raise
        if isinstance(obj, list):
            terms = obj
        elif isinstance(obj, dict) and isinstance(obj.get("terms"), list):
            terms = obj["terms"]
        elif isinstance(obj, dict) and isinstance(obj.get("categories"), dict):
            terms = []
            for category in obj["categories"].values():
                values = category.get("terms") if isinstance(category, dict) else category
                if not isinstance(values, list):
                    explain(shape)
                    raise AuditError("denylist-schema")
                terms.extend(values)
        else:
            explain(shape)
            raise AuditError("denylist-schema")
    else:
        terms = [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")]
    if not terms:
        explain("denylist has no terms" if raw.strip() else "denylist file is empty")
        raise AuditError("denylist-schema")
    if any(not isinstance(t, str) or not t.strip() for t in terms):
        explain("denylist has a blank or non-text term")
        raise AuditError("denylist-schema")
    return [*terms, *owner_patterns(obj)]


def global_credential_helpers() -> list[tuple[str, str]]:
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    result = subprocess.run(["git", "config", "--global", "--includes", "--null", "--get-regexp", r"^credential\.(.+\.)?helper$"],
                            capture_output=True, env=environment)
    if result.returncode:
        raise AuditError("git-credentials-missing")
    return [tuple(os.fsdecode(part) for part in entry.split(b"\n", 1)) for entry in result.stdout.split(b"\0") if entry]


def git(repo: Path, *args: str, timeout: int | None = None, input: bytes | None = None, credentials: bool = False) -> bytes:
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    options = []
    for index, (key, value) in enumerate(global_credential_helpers() if credentials else []):
        environment["COLDRELEASE_CREDENTIAL_HELPER_%d" % index] = value
        options.append("--config-env=%s=COLDRELEASE_CREDENTIAL_HELPER_%d" % (key, index))
    result = subprocess.run(["git", *options, "-C", str(repo), *args], capture_output=True, env=environment, timeout=timeout, input=input)
    if result.returncode:
        raise AuditError("git-read-failed")
    return result.stdout


def git_repository(repo: Path, *args: str) -> bytes:
    try:
        return git(repo, *args)
    except AuditError:
        explain("repository path is not a git repository" if os.path.isdir(repo) else "repository path does not exist or is not a directory")
        raise


def commit_text(raw: bytes) -> bytes:
    """Include author, committer and message; public signatures aren't secrets."""
    headers, separator, message = raw.partition(b"\n\n")
    identity = b"\n".join(line for line in headers.splitlines() if line.startswith((b"author ", b"committer ", b"encoding ")))
    return identity + separator + message


EXPORT_IDENTITY = ("Release Export", "release-export")
GENERIC_HOME_USERS = {"user", "username", "runner", "ubuntu", "root", "admin", "shared", "guest", "home", "you", "your-name", "yourname", "example"}


def export_terms(denylist: list[str], repo: Path) -> list[str]:
    terms = set()
    fields = git(repo, "log", "--all", "--reflog", "--format=%an%x00%ae%x00%cn%x00%ce%x00").decode("utf-8", "replace").split("\0")
    for name, email in zip(fields[0::2], fields[1::2]):
        name, email = name.strip(), email.strip()
        if name.endswith("[bot]") or email.casefold().split("@")[0] in {"noreply", "no-reply"}:
            continue
        terms.add(name)
        if "@" in email and "noreply" not in email.casefold():
            terms.add(email)
    patches = git(repo, "log", "--all", "--reflog", "-p", "-m", "--no-ext-diff", "--no-textconv", "--format=").decode("utf-8", "replace")
    for match in re.finditer(PATTERNS["home-path"], patches):
        user = re.match(r"[\w.-]*", re.split(r"[\\/]+", match.group())[-1]).group().rstrip(".")
        if re.search(r"[^\W\d_]", user) and user.casefold() not in GENERIC_HOME_USERS:
            terms.add(user)
    export_identity = {value.casefold() for value in EXPORT_IDENTITY}
    known = {term.casefold() for term in denylist if isinstance(term, str)}
    return [*denylist, *sorted(term for term in terms if term.casefold() not in known and len(term) >= 3 and "�" not in term and term.casefold() not in export_identity)]


def match_path(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(Path(path).name, p) or path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in patterns)


def visible_files(repo: Path) -> tuple[set[str], set[str]]:
    tracked = {os.fsdecode(p) for p in git(repo, "ls-files", "-z").split(b"\0") if p}
    untracked = {os.fsdecode(p) for p in git(repo, "ls-files", "-z", "--others", "--exclude-standard").split(b"\0") if p}
    return tracked, untracked


def worktree_files(repo: Path) -> tuple[list[str], set[str]]:
    tracked, untracked = visible_files(repo)
    untracked = {p for p in untracked if not GENERATED.intersection(Path(p).parts)}
    return sorted(tracked | untracked), tracked


def symlinked(repo: Path, rel: str) -> bool:
    parts = Path(rel.rstrip("/")).parts
    return any(repo.joinpath(*parts[:end]).is_symlink() for end in range(1, len(parts) + 1))


def excluded_path(path: str, patterns: list[str]) -> bool:
    parts = Path(path).parts
    return any(match_path("/".join(parts[:end]), patterns) for end in range(1, len(parts) + 1))


def blank_env_example(path: str, raw: bytes) -> bool:
    return path == ".env.example" and re.fullmatch(rb"(?:[A-Za-z_][A-Za-z0-9_]*=\n)+", raw) is not None


def protected(path: str) -> bool:
    return bool(re.search(r"(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*|UPSTREAM[^/]*|THIRD_PARTY[^/]*)$", path, re.I))


def inside_letter_component(text: str, start: int, end: int) -> bool:
    """Downgrade only a substring confined to one longer Unicode letter component.

    Punctuation/digits delimit components. Camel-case transitions also delimit
    them; crossing a transition or touching an uncertain character stays blocking.
    Use original case and offsets, never a casefolded copy of the input.
    """
    def upper(char):
        return char.isupper() or unicodedata.category(char) == "Lt"

    def camel_boundary(position):
        if not 0 < position < len(text):
            return False
        previous, current = text[position - 1], text[position]
        return ((previous.islower() and upper(current))
                or (upper(previous) and upper(current)
                    and position + 1 < len(text) and text[position + 1].islower()))

    # Marks can belong to a letter; invisible/undecodable text is also uncertain.
    if any(unicodedata.category(char).startswith("M")
           or unicodedata.category(char) in {"Cf", "Cs"} or char == "\ufffd"
           for char in text[max(0, start - 1):end + 1]):
        return False
    if any(camel_boundary(position) for position in range(start + 1, end)):
        return False
    # HTTPcat could mean HTTP + cat rather than HTT + Pcat. Never downgrade
    # a hit at that ambiguous acronym-to-lowercase join.
    if start >= 2 and upper(text[start - 2]) and upper(text[start - 1]) and text[start].islower():
        return False
    return ((start > 0 and text[start - 1].isalpha() and not camel_boundary(start))
            or (end < len(text) and text[end].isalpha() and not camel_boundary(end)))


class ArchiveLimit(Exception):
    pass


def archive_kind(raw: bytes) -> str | None:
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if raw.startswith(b"\x1f\x8b"):
        return "gzip"
    if raw[257:262] == b"ustar":
        return "tar"
    if raw.startswith(b"%PDF-"):
        return "pdf"
    return None


def take(budget: list[int], size: int):
    budget[0] -= size
    budget[1] -= 1
    if budget[0] < 0 or budget[1] < 0:
        raise ArchiveLimit


def archive_members(kind: str, raw: bytes, path: str, budget: list[int]):
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                take(budget, info.file_size)
                yield info.filename, b"" if info.is_dir() else archive.read(info)
    elif kind == "tar":
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                take(budget, member.size if member.isfile() else 0)
                yield member.name, archive.extractfile(member).read() if member.isfile() else member.linkname.encode("utf-8", "surrogateescape")
    elif kind == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
            data = handle.read(max(budget[0], 0) + 1)
        take(budget, len(data))
        name = path.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        yield name[:-4] + ".tar" if name.lower().endswith(".tgz") else name[:-3] if name.lower().endswith(".gz") else "content", data
    else:
        view = memoryview(raw)
        for number, match in enumerate(re.finditer(rb"(?<!end)stream\r?\n", raw), 1):
            decoder = zlib.decompressobj()
            try:
                data = decoder.decompress(view[match.end():], max(budget[0], 0) + 1)
            except zlib.error:
                continue
            take(budget, len(data))
            yield "stream/" + str(number), data



def tiff_fields(data: bytes, fields: list[str]):
    order = {b"II": "<", b"MM": ">"}[data[:2]]
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 8: 2, 9: 4, 10: 8}
    numbers = {3: "H", 4: "I", 5: "II", 8: "h", 9: "i", 10: "ii"}
    pending, seen = [struct.unpack(order + "I", data[4:8])[0]], set()
    while pending:
        offset = pending.pop()
        if offset in seen:
            continue
        if offset + 2 > len(data):
            raise ValueError("TIFF directory outside the block")
        seen.add(offset)
        for index in range(struct.unpack(order + "H", data[offset:offset + 2])[0]):
            entry = offset + 2 + 12 * index
            tag, kind, count = struct.unpack(order + "HHI", data[entry:entry + 8])
            size = sizes.get(kind, 1) * count
            start = entry + 8 if size <= 4 else struct.unpack(order + "I", data[entry + 8:entry + 12])[0]
            if start + size > len(data):
                raise ValueError("TIFF value outside the block")
            value = data[start:start + size]
            if tag in {0x8769, 0x8825}:
                pending.append(struct.unpack(order + "I", value[:4])[0])
            elif 0x9C9B <= tag <= 0x9C9F:
                fields.append(value.decode("utf-16-le", "replace").strip("\0 "))
            elif tag == 0x9286 and value.startswith(b"UNICODE\0"):
                fields.append(value[8:].decode("utf-16-le" if order == "<" else "utf-16-be", "replace").strip("\0 "))
            elif kind in numbers:
                fields.append(" ".join(map(str, struct.unpack(order + numbers[kind] * count, value))))
            else:
                fields.append(value.decode("utf-8", "replace").strip("\0 "))


def jpeg_segments(raw: bytes):
    index = 2
    while index + 2 <= len(raw) and raw[index] == 0xFF and raw[index + 1] != 0xD9:
        marker = raw[index + 1]
        if marker == 0xFF:
            index += 1
            continue
        end = index + 2
        if not (marker == 0x01 or 0xD0 <= marker <= 0xD7):
            if index + 4 > len(raw):
                break
            end += struct.unpack(">H", raw[index + 2:index + 4])[0]
        if marker == 0xDA:
            following = re.compile(rb"\xff(?![\x00\xd0-\xd7\xff])").search(raw, end)
            end = following.start() if following else len(raw)
        yield marker, raw[index:end]
        index = end
    yield None, raw[index:]


def png_chunks(raw: bytes):
    index = 8
    while index + 12 <= len(raw):
        end = index + 12 + struct.unpack(">I", raw[index:index + 4])[0]
        if end > len(raw):
            raise ValueError("truncated PNG chunk")
        yield raw[index + 4:index + 8], raw[index:end]
        index = end


def pdf_literal(raw: bytes, start: int) -> bytes:
    depth, index = 0, start
    while index < len(raw):
        if raw[index] == 0x5C:
            index += 1
        elif raw[index] == 0x28:
            depth += 1
        elif raw[index] == 0x29:
            depth -= 1
            if not depth:
                return raw[start:index + 1]
        index += 1
    raise ValueError("unterminated PDF string")


def pdf_string(token: bytes) -> str:
    if token.startswith(b"<"):
        digits = re.sub(rb"\s", b"", token[1:-1]).decode()
        data = bytes.fromhex(digits + "0" * (len(digits) % 2))
    else:
        escapes = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"\n": b"", b"\r": b"", b"\r\n": b""}
        data = re.sub(rb"\\(\r\n|[0-7]{1,3}|.)", lambda m: bytes([int(m.group(1), 8) & 255]) if m.group(1)[:1].isdigit()
                      else escapes.get(m.group(1), m.group(1)), token[1:-1], flags=re.S)
    return data.decode("utf-16", "replace") if data.startswith((b"\xfe\xff", b"\xff\xfe")) else data.decode("latin-1")


def metadata_blocks(raw: bytes):
    if raw.startswith(b"\xff\xd8"):
        for marker, segment in jpeg_segments(raw):
            if marker == 0xE1 and segment[4:10] == b"Exif\0\0":
                yield b"eXIf", segment[10:]
    elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
        for kind, chunk in png_chunks(raw):
            if kind in {b"eXIf", b"tEXt", b"zTXt", b"iTXt"}:
                yield kind, chunk[8:-4]
    elif raw.startswith(b"%PDF-"):
        gap = rb"(?:\s|%[^\r\n]*)*"
        for match in re.finditer(rb"/(?:Author|Creator|Producer|Title|Subject|Keywords)" + gap + rb"(?:([(<])|(\d+)\s+(\d+)\s+R\b)", raw):
            if match.group(1):
                yield b"pdf", match.start(1)
            else:
                target = re.compile(rb"(?<!\d)" + match.group(2) + rb"\s+" + match.group(3) + rb"\s+obj" + gap + rb"([(<])").search(raw)
                yield b"pdf", target.start(1) if target else -1


def metadata_field(kind: bytes, data, raw: bytes, budget: list[int], fields: list[str]):
    if kind == b"eXIf":
        return tiff_fields(data, fields)
    if kind == b"pdf":
        if data < 0:
            raise ValueError("unresolved PDF reference")
        hexadecimal = re.compile(rb"<[0-9A-Fa-f\s]*>").match(raw, data)
        if raw[data:data + 1] == b"<" and not hexadecimal:
            raise ValueError("PDF value is not a string")
        return fields.append(pdf_string(hexadecimal.group() if hexadecimal else pdf_literal(raw, data)))
    key, _, rest = data.partition(b"\0")
    if kind == b"iTXt":
        compressed, rest = rest[:1] == b"\1", rest[2:].split(b"\0", 2)[2]
    else:
        compressed = kind == b"zTXt"
        rest = rest[1:] if compressed else rest
    if compressed:
        decompressor = zlib.decompressobj()
        rest = decompressor.decompress(rest, max(budget[0], 0) + 1)
        take(budget, len(rest))
        if not decompressor.eof:
            raise ValueError("truncated compressed text")
    fields.append(key.decode("latin-1") + ": " + rest.decode("utf-8" if kind == b"iTXt" else "latin-1", "replace"))


def metadata_text(raw: bytes, budget: list[int]) -> tuple[bytes, set[str]]:
    """Decoded author, GPS, software and creator fields that raw-byte scanning cannot read, and coverage problems."""
    fields, problems = [], set()
    try:
        for kind, data in metadata_blocks(raw):
            try:
                metadata_field(kind, data, raw, budget, fields)
            except (KeyError, IndexError, ValueError, struct.error, zlib.error):
                problems.add("metadata-unreadable")
    except (IndexError, ValueError, struct.error):
        problems.add("metadata-unreadable")
    except ArchiveLimit:
        problems.add("archive-limit")
    return "\n".join(fields).encode(), problems


def strip_metadata(raw: bytes) -> bytes | None:
    try:
        if raw.startswith(b"\xff\xd8"):
            return raw[:2] + b"".join(part for marker, part in jpeg_segments(raw) if marker not in {0xE1, 0xED, 0xFE})
        if raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return raw[:8] + b"".join(chunk for kind, chunk in png_chunks(raw) if kind not in {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"})
    except (ValueError, struct.error):
        pass
    return None


class Scanner:
    def __init__(self, terms: list, private_repos: list[str] = (), approvals: list[dict] = ()):
        self.terms = [term for term in terms if isinstance(term, str)]
        self.owner_patterns = {item["kind"]: multiline(item["pattern"]) for item in terms if isinstance(item, dict)}
        self.patterns = {**PATTERNS, **self.owner_patterns}
        self.private_repos = list(private_repos)
        refs = {private_repo_ref(url) for url in self.private_repos}
        names = {re.split(r"[/:]", ref)[-1] for ref in refs if "://" not in ref and "@" not in ref} - {""}
        self.private_redactions = sorted({*self.private_repos, *(ref for ref in refs if "/" in ref)})
        self.private_names = [re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.I) for name in sorted(names, key=len, reverse=True)]
        self.approvals = list(approvals)
        self.matched_approvals: set[int] = set()
        self.fingerprint_upgrades: list[dict] = []
        self.findings: list[dict] = []
        self.stats = Counter()
        self.seen = set()

    def safe_path(self, path: str) -> str:
        # Paths themselves can contain private terms, emails, IPs or tokens.
        original = path
        for term in self.terms:
            if term.casefold() in path.casefold() or re.search(re.escape(term), path, re.I):
                return "[path-" + fingerprint(original) + "]"
        for pattern in [*self.patterns.values(), *SECRET_PATTERNS.values(), r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"]:
            if re.search(pattern, path, re.I):
                return "[path-" + fingerprint(original) + "]"
        if any(url.casefold() in path.casefold() for url in self.private_redactions) or any(name.search(path) for name in self.private_names):
            return "[path-" + fingerprint(original) + "]"
        if re.search(r"[0-9A-Fa-f]*:[0-9A-Fa-f:]+", path):
            return "[path-" + fingerprint(original) + "]"
        if any(opaque_secret(value) for value in re.findall(r"[A-Za-z0-9_+=-]{32,}", path)):
            return "[path-" + fingerprint(original) + "]"
        return path.replace("\n", "[newline]").replace("\r", "[return]").replace("\t", "[tab]")

    def add(self, scope: str, category: str, kind: str, path: str, line: int = 0, value: str | bytes = b"", term_index: int | None = None, object_id: str | None = None, details: dict | None = None, source_sha256: str | None = None, column: int | None = None, legacy_value: str | bytes | None = None):
        item = {"scope": scope, "category": category, "kind": kind, "path": self.safe_path(path), "line": line, "fingerprint": fingerprint(value)}
        if source_sha256 is not None:
            item["source_sha256"] = source_sha256
        if column is not None:
            item["column"] = column
        if term_index is not None:
            item["term_index"] = term_index
        if object_id:
            item["object"] = object_id
        # Approvals are specific to kind, path, scope and fingerprint.
        licence_review = category == "license" and ((kind == "dependency-license-review" and scope == "verification")
                                                   or (kind in {"npm-source-declarations-review", "bun-source-declarations-review"} and scope == "tree"))
        approval_reason = None
        eligible = (category in {"personal", "media"} or licence_review or kind == "denylist"
                    or category == "deployment-config" and kind == "manual-review")
        approved = False
        matched_legacy = matched_current = False
        reviewable_secret = category == "secrets" and kind in {"entropy", "assigned-secret", "credential-url"} and source_sha256 is not None
        needs_reason = licence_review or kind == "denylist" or reviewable_secret
        reviewed_by = None
        for approval_index, approval in enumerate(self.approvals):
            exact = all(approval.get(k) == item[k] for k in ("scope", "kind", "path", "fingerprint"))
            legacy_match = False
            if not exact and legacy_value is not None:
                exact = legacy_match = all(approval.get(k) == item[k] for k in ("scope", "kind", "path")) and approval.get("fingerprint") == fingerprint(legacy_value)
            review = reviewable_secret or category in {"personal", "media"} and "classification" in approval
            reason = approval.get("reason")
            valid_reason = (not (needs_reason or review) or isinstance(reason, str) and bool(reason.strip()) and reason.isprintable()
                            and not any(term.casefold() in reason.casefold() for term in self.terms)
                            and not any(re.search(pattern, reason, re.I) for pattern in self.owner_patterns.values()))
            reviewed_false_positive = (review and approval.get("classification") == "false-positive"
                                       and approval.get("source_sha256") == source_sha256
                                       and approval.get("line") == line and approval.get("column") == column
                                       and (column is not None or not reviewable_secret))
            if (reviewed_false_positive if review else eligible) and exact and valid_reason:
                self.matched_approvals.add(approval_index)
                approved = True
                matched_legacy |= legacy_match
                matched_current |= exact and not legacy_match
                reviewed_by = "false-positive" if review else reviewed_by
                approval_reason = reason if kind == "denylist" or review else approval_reason
        item["reviewed"] = approved
        if matched_legacy and not matched_current:
            upgrade = {"kind": kind, "path": item["path"], "legacy_fingerprint": fingerprint(legacy_value), "fingerprint": item["fingerprint"]}
            if upgrade not in self.fingerprint_upgrades:
                self.fingerprint_upgrades.append(upgrade)
        if item["reviewed"] and kind == "denylist":
            item["review_source"] = "owner approval"
            item["review_status"] = "accepted by owner approval"
            item["reason"] = approval_reason
        if item["reviewed"] and reviewed_by:
            item["review_status"] = "accepted as exact-source false positive"
            item["reason"] = approval_reason
        if details:
            item.update(details)
        key = tuple(sorted(item.items()))
        if key not in self.seen:
            self.seen.add(key)
            self.findings.append(item)
        return item

    def text(self, raw: bytes, scope: str, path: str, object_id: str | None = None, *, source: bool = True):
        self.stats[scope + "_bytes"] += len(raw)
        source_digest = hashlib.sha256(raw).hexdigest() if source else None
        # UTF-16 media metadata and text files still receive term/secret checks.
        encodings = ["utf-8"]
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or (raw and raw.count(b"\0") / len(raw) > .15):
            encodings += ["utf-16-le", "utf-16-be"]
        for encoding in encodings:
            text = raw.decode(encoding, errors="replace")
            expressions = python_expression_spans(text, path) if source else {}
            integrity = npm_integrity_spans(text, path) if encoding == "utf-8" else []
            for index, term in enumerate(self.terms):
                pattern = re.escape(term)
                alphabetic = term.isalpha()
                if alphabetic:
                    # Include overlapping occurrences so an embedded hit cannot
                    # conceal a later component/whole-word occurrence.
                    pattern = "(?=(" + pattern + "))"
                elif len(term) <= 3 and term.isalnum():
                    # Short machine aliases are words, not substrings of lockfile hashes.
                    pattern = r"(?<![A-Za-z0-9])" + pattern + r"(?![A-Za-z0-9])"
                for match in re.finditer(pattern, text, re.I):
                    group = 1 if alphabetic else 0
                    start, end = match.span(group)
                    reviewable = alphabetic and inside_letter_component(text, start, end)
                    self.add(scope, "personal", "denylist", path, text.count("\n", 0, start) + 1, match.group(group), index, object_id,
                             details={"reviewable": True} if reviewable else None, source_sha256=source_digest)
            offset = 0
            for number, full_line in enumerate(text.splitlines(keepends=True), 1):
                line = full_line.splitlines()[0]
                for kind, pattern in PATTERNS.items():
                    for match in re.finditer(pattern, line, re.I):
                        if kind == "internal-host" and any(
                                start <= offset + match.start() and offset + match.end() <= end
                                for start, end in expressions.get(kind, ())):
                            continue
                        if kind == "email" and re.fullmatch(
                                r"(?:[0-9]+\+(?=[A-Za-z0-9-]{1,39}@)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*@users\.noreply\.github\.com|noreply@github\.com)",
                                match.group()) and (
                                match.start() == 0 or line[match.start() - 1] not in "!#$%&'*+/=?^_`{|}~@") and not re.match(
                                    r'@|[^"\r\n]*"@', line[match.end():]):
                            continue
                        if kind == "private-repo-url" and not private_repo_url(match.group()):
                            continue
                        self.add(scope, "personal", kind, path, number, match.group(), object_id=object_id, source_sha256=source_digest)
                own_name_spans = set()
                for url in self.private_repos:
                    ref = private_repo_ref(url)
                    tail = len(re.split(r"[/:]", ref)[-1])
                    for match in re.finditer(re.escape(ref), line, re.I):
                        own_name_spans.add((match.end() - tail, match.end()))
                        self.add(scope, "personal", "private-repo-url", path, number, match.group(), object_id=object_id, source_sha256=source_digest)
                for name in self.private_names:
                    match = name.search(line)
                    while match:
                        if match.span() not in own_name_spans:
                            self.add(scope, "personal", "private-repo-url", path, number, match.group(), object_id=object_id, source_sha256=source_digest)
                        match = name.search(line, match.start() + 1)
                for candidate in re.finditer(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[\w-]+)?(?![\w:])", line):
                    value = candidate.group()
                    if value == "::" and not (candidate.start() > 0 and line[candidate.start() - 1] in "\"'["):
                        continue  # classifier/prose punctuation, not an address literal
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    kind = "tailnet-ip" if address.version == 4 and not address.is_global and not address.is_private else "ipv" + str(address.version)
                    self.add(scope, "personal", kind, path, number, value, object_id=object_id, source_sha256=source_digest)
                for kind, pattern in SECRET_PATTERNS.items():
                    if kind == "assigned-secret":
                        pattern = "(?i)(?=" + pattern.removeprefix("(?i)") + ")"
                    elif kind == "credential-url":
                        pattern = "(?=(" + pattern + "))"
                    for match in re.finditer(pattern, line):
                        group = match.lastindex or 0
                        if kind == "credential-url" and any(
                                start == offset + match.start(group) and offset + match.end(group) >= end
                                for start, end in expressions.get(kind, ())):
                            continue
                        if kind == "assigned-secret" and any(
                                start <= offset + match.start(group) and offset + match.end(group) <= end
                                for start, end in expressions.get(kind, ())):
                            continue
                        self.add(scope, "secrets", kind, path, number, match.group(group), object_id=object_id,
                                 source_sha256=source_digest, column=match.start(group) + 1)
                for match in re.finditer(r"(?<![\w+/=-])[A-Za-z0-9_+=-]{32,}(?![\w+/=-])", line):
                    value = match.group()
                    # A hexadecimal content digest is not itself a credential. Explicit
                    # key formats and labelled secrets above still take precedence.
                    if opaque_secret(value) and not any(
                            start <= offset + match.start() and offset + match.end() <= end
                            for start, end in integrity):
                        self.add(scope, "secrets", "entropy", path, number, value, object_id=object_id,
                                 source_sha256=source_digest, column=match.start() + 1)
                offset += len(full_line)
            for kind, pattern in self.owner_patterns.items():
                for match in re.finditer(pattern, text, re.I):
                    self.add(scope, "personal", kind, path, len((text[:match.start()] + "x").splitlines()), match.group(),
                             object_id=object_id, source_sha256=source_digest)

    def file(self, raw: bytes, scope: str, path: str, object_id: str | None = None, budget: list[int] | None = None, depth: int = 0):
        if budget is None:
            self.stats[scope + "_files"] += 1
            budget = [ARCHIVE_MAX_BYTES, ARCHIVE_MAX_MEMBERS]
        self.text(path.encode("utf-8", errors="surrogateescape"), scope, path, object_id, source=False)
        self.text(raw, scope, path, object_id)
        limited = self.metadata(raw, scope, path, object_id, budget)
        member = Path(path.rsplit("!", 1)[-1])
        name, suffix = member.name.lower(), member.suffix.lower()
        if depth and suffix == ".xml":
            self.text(html.unescape(re.sub(r"<[^>]*>", "", raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8", "replace"))).encode(), scope, path, object_id)
        if (name == ".env" or name.startswith(".env.")) and not blank_env_example(path, raw) or re.search(r"(?:^|[_.-])(?:tokens?|credentials|id_rsa|id_ed25519)(?:[_.-]|$)", name) or suffix in {".pem", ".key", ".p12", ".pfx"}:
            self.add(scope, "secrets", "credential-file", path, value=raw, object_id=object_id)
        limited |= self.expand(raw, scope, path, object_id, budget, depth)
        if suffix in MEDIA or archive_kind(raw) == "pdf":
            self.add(scope, "media", "manual-review", path, value=raw, object_id=object_id)
        if suffix not in MEDIA and not limited and (archive_kind(raw) in {"zip", "tar", "gzip"} or suffix in {".zip", ".gz", ".tar", ".7z", ".exe", ".dll", ".so", ".sqlite", ".db", ".bin"} or (b"\0" in raw and not raw.startswith((b"\xff\xfe", b"\xfe\xff")))):
            self.add(scope, "media", "binary-review", path, value=raw, object_id=object_id)
        if raw.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            self.add(scope, "coverage", "lfs-content-not-scanned", path, value=raw, object_id=object_id)
        self.deployment(raw, scope, path, object_id)
        return limited

    def metadata(self, raw: bytes, scope: str, path: str, object_id: str | None, budget: list[int]) -> bool:
        fields, problems = metadata_text(raw, budget)
        if fields:
            self.text(fields, scope, path + "!metadata", object_id)
        for kind in sorted(problems):
            self.add(scope, "coverage", kind, path, value=raw, object_id=object_id)
        return "archive-limit" in problems

    def deployment(self, raw: bytes, scope: str, path: str, object_id: str | None):
        def flag(kind, line=0, value=raw):
            self.add(scope, "deployment-config", kind, path, line, value, object_id=object_id)

        rel, name = path.replace("\\", "/").lower(), Path(path).name.lower()
        if ".tfstate" in name or re.search(r"\.tfvars(?:\.json)?$", name):
            flag("deployment-state")
        if re.fullmatch(r"kubeconfig(?:\.[\w-]+)?|[\w.-]+\.kubeconfig", name) or re.search(r"(?:^|/)\.kube/config$", rel):
            flag("kubeconfig")
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()

        def assignments(pattern):
            for number, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line):
                    if literal_value(match.group(1), yaml=False):
                        flag("registry-auth", number, match.group(1))

        if name == ".npmrc":
            assignments(r"^[^#;]*?(?:_authToken|_auth|_password)\s*=\s*(.*)$")
        elif name == ".pypirc":
            assignments(r"(?i)^\s*password\s*[:=]\s*(.*)$")
        elif re.search(r"(?:^|/)\.docker/config\.json$", rel):
            assignments(r'"(?:auth|identitytoken|registrytoken)"\s*:\s*"([^"]+)"')
        if name.endswith((".yaml", ".yml")):
            for number in sorted({*kubernetes_secret_data(lines), *flow_secret_data(text)}):
                flag("kubernetes-secret", number, lines[number - 1])
        entries, yaml = [], True
        workflow = re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$|(?:^|/)action\.ya?ml$", rel)
        if workflow:
            entries = list(yaml_block_lines(text, {"env", "with"}))
            for number, value in yaml_block_lines(text, {"runs-on"}):
                if re.search(r"(?<![\w-])self-hosted(?![\w-])", value):
                    flag("manual-review", number, value)
        elif re.fullmatch(r"(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml", name):
            entries = list(yaml_block_lines(text, {"environment"}))
        elif name in {"dockerfile", "containerfile"} or name.startswith(("dockerfile.", "containerfile.")) or name.endswith(".dockerfile"):
            logical, yaml = [], False
            for index, line in enumerate(lines, 1):
                if logical and logical[-1][1].endswith("\\"):
                    logical[-1] = (logical[-1][0], logical[-1][1][:-1] + " " + line)
                else:
                    logical.append((index, line))
            for number, line in logical:
                instruction = re.match(r"(?i)\s*(ENV|ARG)\s+(.*)$", line)
                if not instruction:
                    continue
                body = instruction.group(2)
                pairs = re.findall(r"([A-Za-z_][\w.-]*)=(\"[^\"]*\"|'[^']*'|\S*)", body)
                if not pairs and instruction.group(1).upper() == "ENV":
                    legacy = body.split(None, 1)
                    pairs = [tuple(legacy)] if len(legacy) == 2 else []
                entries += [(number, f"{key}={value}") for key, value in pairs]
        entries = [(number, part) for number, entry in entries
                   for part in (flow_items(entry[1:-1]) if entry.startswith("{") and entry.endswith("}") else [entry])]
        for number, entry in entries:
            entry = entry.strip()
            match = re.match(r"(?:-\s*)?[\"']?([A-Za-z_][\w.-]*)[\"']?\s*(?::(?:\s|$)|=)(.*)$", entry)
            if match and re.search(DEPLOYMENT_SECRET_KEY, match.group(1)) and literal_value(match.group(2), yaml):
                flag("literal-secret", number, match.group(2).strip())

    def expand(self, raw: bytes, scope: str, path: str, object_id: str | None, budget: list[int], depth: int) -> bool:
        kind = archive_kind(raw)
        limited = False
        if kind is None:
            return False
        try:
            if depth >= ARCHIVE_MAX_DEPTH:
                raise ArchiveLimit
            for name, data in archive_members(kind, raw, path, budget):
                if kind == "pdf":
                    self.text(data, scope, path + "!" + name, object_id)
                    self.metadata(b"%PDF-" + data, scope, path + "!" + name, object_id, budget)
                else:
                    limited |= self.file(data, scope, path + "!" + name, object_id, budget, depth + 1)
        except ArchiveLimit:
            self.add(scope, "coverage", "archive-limit", path, value=raw, object_id=object_id)
            return True
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, RuntimeError, NotImplementedError, ValueError, zlib.error):
            pass
        return limited

    def tree(self, repo: Path):
        paths, tracked = worktree_files(repo)
        for rel in paths:
            rel = rel.rstrip("/")
            path = repo / rel
            if path.is_symlink():
                raw = os.readlink(path).encode()
                self.file(raw, "tree", rel)
                self.add("tree", "coverage", "symlink", rel, value=raw)
            elif symlinked(repo, rel):
                self.add("tree", "coverage", "symlink", rel)
            elif path.is_dir():
                self.add("tree", "coverage", "nested-repository", rel)
            elif not path.exists():
                self.add("tree", "coverage", "missing-tracked-file", rel)
            else:
                try:
                    self.file(path.read_bytes(), "tree", rel)
                except OSError:
                    self.add("tree", "coverage", "unreadable", rel)

    def history(self, repo: Path):
        if git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
            self.add("history", "coverage", "shallow-history", "@git")
        commits = git(repo, "rev-list", "--all", "--reflog").splitlines()
        self.stats["history_commits"] = len(commits)
        if not commits:
            self.add("history", "coverage", "no-commits", "@git")
        seen = set()
        for commit in commits:
            oid = commit.decode("ascii")
            self.text(commit_text(git(repo, "cat-file", "commit", oid)), "metadata", "@commit/" + oid[:12], oid)
            entries = git(repo, "ls-tree", "-r", "-z", oid).split(b"\0")
            for entry in filter(None, entries):
                metadata, path = entry.split(b"\t", 1)
                mode, kind, blob = metadata.split()
                rel = path.decode("utf-8", "surrogateescape")
                key = (blob, path, mode)
                if key in seen:
                    continue
                seen.add(key)
                if kind != b"blob":
                    self.add("history", "coverage", "submodule", rel, object_id=oid)
                    continue
                raw = git(repo, "cat-file", "blob", blob.decode())
                self.file(raw, "history", rel, blob.decode())
                if mode == b"120000":
                    self.add("history", "coverage", "symlink", rel, value=raw, object_id=oid)


def unique_json_object(pairs):
    """Repeated keys must not discard an earlier licence or gate assertion."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate-json-key')
        obj[key] = value
    return obj


MANIFEST_NAMES = ("coldrelease.json", "release-check.json")


def default_manifest(repo: Path) -> Path:
    present = [repo / name for name in MANIFEST_NAMES if (repo / name).exists()]
    if len(present) == 2 and present[0].read_bytes() != present[1].read_bytes():
        raise AuditError("manifest-conflict", " and ".join(MANIFEST_NAMES) + " differ; keep only one")
    return present[0] if present else repo / MANIFEST_NAMES[0]


def manifest_for(repo: Path, path: Path | None) -> dict:
    given = path is not None
    default = default_manifest(repo)
    path = path or default
    if not given and not path.exists():
        return {"exclude": [], "approvals": [], "quickstart": [], "checks": []}
    try:
        text = path.read_text()
    except OSError:
        explain("manifest file does not exist or cannot be read")
        raise
    try:
        obj = json.loads(text, object_pairs_hook=unique_json_object)
    except json.JSONDecodeError:
        explain("manifest file is not valid JSON")
        raise
    if not isinstance(obj, dict):
        raise AuditError("manifest-schema", "the manifest must be a JSON object")
    unknown = [k for k in obj if k not in MANIFEST_KEYS]
    if unknown:
        raise AuditError("manifest-schema", "unknown top-level keys: " + ", ".join(unknown)
                         + "; allowed keys: " + ", ".join(MANIFEST_KEYS))
    for key in ("exclude", "approvals", "quickstart", "checks"):
        obj.setdefault(key, [])
        if not isinstance(obj[key], list):
            raise AuditError("manifest-schema", f"{key} must be a list")
    for key in ("approvals", "quickstart", "checks"):
        if any(not isinstance(item, dict) for item in obj[key]):
            raise AuditError("manifest-schema", f"every item in {key} must be an object")
    for key in ("quickstart", "checks"):
        if any("timeout" in item and (type(item["timeout"]) is not int or item["timeout"] < 1) for item in obj[key]):
            raise AuditError("manifest-schema", f"{key} timeout must be a whole number of seconds greater than 0")
    if not isinstance(obj.get("dependency_licenses", {}), dict):
        raise AuditError("manifest-schema", "dependency_licenses must be an object")
    verify_tools(obj)
    if any(not isinstance(p, str) or p.startswith("/") or ".." in Path(p).parts for p in obj["exclude"]):
        raise AuditError("manifest-path")
    return obj


def verify_tools(manifest: dict) -> list[str]:
    tools = manifest.get("verify_tools", [])
    if not isinstance(tools, list):
        raise AuditError("manifest-schema", "verify_tools must be a list of tool names")
    if len(tools) > 8:
        raise AuditError("manifest-schema", "verify_tools may list at most 8 tools")
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._+-]+", name) or name in {".", ".."} for name in tools):
        raise AuditError("manifest-schema", "every verify_tools entry must be a string of letters, digits and . _ + -")
    if len(set(tools)) != len(tools):
        raise AuditError("manifest-schema", "verify_tools must not repeat a tool")
    return tools


def dependency_free_package(repo: Path, path: Path, scanner: Scanner, identifier: str | None) -> bool:
    def invalid_constant(value):
        raise ValueError("invalid-json-constant")
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
            return False
        with path.open("rb") as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            return False
        package = json.loads(raw, object_pairs_hook=unique_json_object, parse_constant=invalid_constant)
    except (OSError, ValueError, RecursionError):
        return False
    if not isinstance(package, dict):
        return False
    if "license" in package and (not isinstance(package["license"], str) or package["license"] != identifier):
        scanner.add("tree", "license", "license-metadata-mismatch", path.relative_to(repo).as_posix(), value=json.dumps(package["license"], sort_keys=True))
    if "licenses" in package or package.get("gypfile"):
        return False
    if any(key in package and not isinstance(package[key], dict)
           for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")):
        return False
    if any(package.get(key) for key in ("dependencies", "devDependencies", "optionalDependencies",
                                       "peerDependencies", "bundledDependencies", "bundleDependencies",
                                       "workspaces", "overrides", "resolutions")):
        return False
    scripts = package.get("scripts", {})
    if not isinstance(scripts, dict) or any(not isinstance(value, str) for value in scripts.values()):
        return False
    if any(name in {"install", "prepare", "publish", "dependencies"}
           or name.startswith(("pre", "post")) for name in scripts):
        return False
    return True


def node_packages(repo: Path) -> tuple[list[Path], list[Path], bool]:
    packages, hooks = [], []
    artifacts = os.path.lexists(repo / "node_modules")
    lockfiles = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}
    for rel in worktree_files(repo)[0]:
        parts = Path(rel).parts
        if parts[-1] == "package.json":
            packages.append(repo / rel)
        if parts[-1] == "binding.gyp":
            hooks.append(repo / rel)
    tracked, untracked = visible_files(repo)
    for rel in tracked | untracked:
        parts = Path(rel).parts
        if parts[-1] in lockfiles or "node_modules" in parts or (parts[-1] == "binding.gyp" and rel in tracked):
            artifacts = True
    return packages, hooks, artifacts


def npm_source_scope(repo: Path, manifest: dict, *, legacy_modes: bool = False) -> dict | None:
    """Bind the audited source tree; an approval must review its provenance too."""
    entries = []
    tracked, untracked = visible_files(repo)
    forbidden_dirs = {"node_modules", "dist", "build", ".venv", "venv", "site-packages"}
    forbidden_suffixes = {".node", ".so", ".dll", ".dylib", ".exe", ".wasm", ".a", ".o", ".zip", ".gz", ".tgz", ".tar", ".whl", ".jar", ".pyc"}
    caches = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    try:
        for rel in sorted(tracked | untracked):
            parts = Path(rel.rstrip("/")).parts
            if symlinked(repo, rel) or forbidden_dirs.intersection(parts[:-1]):
                return None
            if caches.intersection(parts[:-1]):
                if rel in tracked:
                    return None
                continue
            name = parts[-1]
            path = repo / rel
            if name in {"npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
                return None
            if name in {"package-lock.json", "bun.lock", "bun.lockb"} and not path.with_name("package.json").is_file():
                return None
            if not stat.S_ISREG(path.lstat().st_mode) or path.suffix.lower() in forbidden_suffixes:
                return None
            raw = path.read_bytes()
            if raw.startswith((b"\x7fELF", b"MZ", b"\x00asm", b"PK\x03\x04", b"\x1f\x8b", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
                return None
            if name != "bun.lockb" and path.suffix.lower() not in MEDIA | {".ico", ".woff", ".woff2", ".ttf", ".otf"}:
                if b"\0" in raw:
                    return None
                raw.decode("utf-8")
            if rel in MANIFEST_NAMES:
                config = json.loads(raw, object_pairs_hook=unique_json_object)
                raw = canonical_json({k: v for k, v in config.items() if k != "approvals"})
            mode = stat.S_IMODE(path.lstat().st_mode)
            if not legacy_modes:
                mode = 0o755 if mode & stat.S_IXUSR else 0o644
            entries.append({"path": rel, "mode": mode, "sha256": sha256(raw)})
        if not tracked.issubset({entry["path"] for entry in entries}):
            return None
        return {"kind": "exact-source-tree-declarations-only-v1", "files": sorted(entries, key=lambda e: e["path"]),
                "policy": {k: v for k, v in manifest.items() if k != "approvals"}}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return None


def npm_source_declarations(repo: Path, path: Path, scope: dict, *, lock_data=None) -> dict | None:
    """Inventory supported npm v3 declarations, without granting redistribution rights."""
    dependency_fields = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    package_name = r"(?:@[a-z0-9_-][a-z0-9._-]*/)?[a-z0-9_-][a-z0-9._-]*"
    def invalid_constant(value):
        raise ValueError("invalid-json-constant")
    def read_json(file):
        if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_METADATA_BYTES:
            raise ValueError("unsupported-npm-file")
        with file.open("rb") as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise ValueError("oversized-npm-file")
        data = json.loads(raw, object_pairs_hook=unique_json_object, parse_constant=invalid_constant)
        if not isinstance(data, dict):
            raise ValueError("invalid-npm-object")
        return raw, data
    def registry_spec(value):
        return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9.*^~<>=|+ -]+", value)) and bool(value.strip())
    def declarations(entry):
        for field in dependency_fields:
            values = entry.get(field, {})
            if not isinstance(values, dict) or any(not re.fullmatch(package_name, name) or not registry_spec(spec) for name, spec in values.items()):
                raise ValueError("unsupported-npm-declaration")
        meta = entry.get("peerDependenciesMeta", {})
        if not isinstance(meta, dict) or any(not re.fullmatch(package_name, name) or not isinstance(value, dict)
                                           or set(value) - {"optional"} or type(value.get("optional", False)) is not bool
                                           for name, value in meta.items()):
            raise ValueError("invalid-npm-peer-metadata")
        if any(key in entry for key in ("workspaces", "resolutions", "bundledDependencies", "bundleDependencies", "link", "inBundle")):
            raise ValueError("unsupported-npm-source")
    try:
        manifest_raw, package = read_json(path)
        lock_raw, lock = read_json(path.with_name("package-lock.json")) if lock_data is None else lock_data
        if type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] != 3 or "dependencies" in lock:
            return None
        packages = lock.get("packages")
        if not isinstance(packages, dict) or not isinstance(packages.get(""), dict) or len(packages) > MAX_PACKAGES:
            return None
        declarations(package)
        if "name" in package and (not isinstance(package["name"], str) or not re.fullmatch(package_name, package["name"])):
            return None
        if "version" in package and (not isinstance(package["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?", package["version"])):
            return None
        if any(lock.get(key) != package.get(key) for key in ("name", "version")):
            return None
        scripts = package.get("scripts", {})
        if not isinstance(scripts, dict) or any(not isinstance(v, str) for v in scripts.values()):
            return None
        if package.get("gypfile") or "licenses" in package or any(name in {"install", "prepare", "publish", "dependencies"} or name.startswith(("pre", "post")) for name in scripts):
            return None
        for key in (*dependency_fields, "name", "version"):
            default = {} if key in dependency_fields else None
            if package.get(key, default) != packages[""].get(key, default):
                return None
        overrides = package.get("overrides", {})
        if not isinstance(overrides, dict) or any(not re.fullmatch(package_name, name) or not registry_spec(spec) for name, spec in overrides.items()):
            return None
        inventory, edges = [], []
        for location, entry in sorted(packages.items()):
            if not isinstance(entry, dict):
                return None
            declarations(entry)
            if location:
                if not re.fullmatch(r"(?:node_modules/" + package_name + r")(?:/node_modules/" + package_name + r")*", location):
                    return None
                if not isinstance(entry.get("version"), str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?", entry["version"]):
                    return None
                if not isinstance(entry.get("resolved"), str) or not re.fullmatch(r"https://registry\.npmjs\.org/[^\s?#]+\.tgz", entry["resolved"]):
                    return None
                if not isinstance(entry.get("integrity"), str) or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", entry["integrity"]):
                    return None
                for flag in ("dev", "optional", "devOptional", "peer", "hasInstallScript"):
                    if flag in entry and type(entry[flag]) is not bool:
                        return None
                for key in ("os", "cpu", "libc"):
                    if key in entry and (not isinstance(entry[key], list) or any(not isinstance(v, str) for v in entry[key])):
                        return None
                label = entry.get("license")
                if label is not None and not isinstance(label, str):
                    return None
                inventory.append({**entry, "path": location, "license": label,
                                  "license_state": licence_expression(label) if label else "unknown"})
            for field in dependency_fields:
                for name, spec in sorted(entry.get(field, {}).items()):
                    # npm resolves at the current package and then each enclosing node_modules.
                    ancestors = location.split("/node_modules/") if location else []
                    prefixes = ["/node_modules/".join(ancestors[:i]) for i in range(len(ancestors), 0, -1)] + [""]
                    target = next((prefix + ("/" if prefix else "") + "node_modules/" + name
                                   for prefix in prefixes if prefix + ("/" if prefix else "") + "node_modules/" + name in packages), None)
                    optional_peer = field == "peerDependencies" and entry.get("peerDependenciesMeta", {}).get(name, {}).get("optional", False)
                    if target is None and not optional_peer:
                        return None
                    edges.append({"from": location, "field": field, "name": name, "spec": spec,
                                  "target": target, "optional_peer": optional_peer})
        return {"schema": 1, "manifest_path": path.relative_to(repo).as_posix(),
                "manifest_sha256": sha256(manifest_raw), "lock_sha256": sha256(lock_raw),
                "inventory": inventory, "edges": edges, "distribution_scope": scope}
    except (OSError, ValueError, TypeError, RecursionError):
        return None


def bun_source_declarations(repo: Path, path: Path, scope: dict) -> dict | None:
    """Translate registry-only Bun resolutions into the existing npm evidence model."""
    package_name = r"(?:@[a-z0-9_-][a-z0-9._-]*/)?[a-z0-9_-][a-z0-9._-]*"
    prerelease = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    exact_version = (r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
                     + r"(?:-" + prerelease + r"(?:\." + prerelease + r")*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
    fields = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    def invalid_constant(value):
        raise ValueError("invalid-json-constant")
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
            return None
        package_raw = path.read_bytes()
        package = json.loads(package_raw, object_pairs_hook=unique_json_object)
        if (not isinstance(package, dict) or package.get("workspaces") or package.get("overrides")
                or package.get("trustedDependencies")
                or any(not isinstance(package.get(field, {}), dict)
                       or any(not re.fullmatch(package_name, name) or not isinstance(spec, str)
                              or not re.fullmatch(r"[A-Za-z0-9.*^~<>=|+ -]+", spec)
                              for name, spec in package.get(field, {}).items()) for field in fields)):
            return None
        locks = [p for name in ("bun.lock", "bun.lockb", "package-lock.json") if (p := path.with_name(name)).exists()]
        if len(locks) != 1 or locks[0].name == "package-lock.json":
            return None
        lock_path = locks[0]
        if lock_path.is_symlink() or not lock_path.is_file() or lock_path.stat().st_size > MAX_METADATA_BYTES:
            return None
        raw = lock_path.read_bytes()
        text_raw = raw
        if lock_path.name == "bun.lockb":
            bun = shutil.which("bun")
            if not bun:
                return None
            # Only copied declarations enter the converter. No project config or hooks run.
            with tempfile.TemporaryDirectory(prefix="release-check-bun-") as temp:
                directory = Path(temp)
                (directory / "bun.lockb").write_bytes(raw)
                (directory / "package.json").write_bytes(package_raw)
                (directory / "bunfig.toml").write_text("")
                with (directory / "converter.log").open("wb") as log:
                    converted = subprocess.run([str(Path(bun).resolve()), "install", "--config=" + str(directory / "bunfig.toml"),
                                                "--save-text-lockfile", "--frozen-lockfile", "--lockfile-only",
                                                "--ignore-scripts", "--offline", "--cache-dir=" + str(directory / "cache")],
                                               cwd=directory, env={"PATH": os.defpath}, stdout=log, stderr=log, timeout=30)
                output = directory / "bun.lock"
                if converted.returncode or not output.is_file() or output.stat().st_size > MAX_METADATA_BYTES or (directory / "node_modules").exists():
                    return None
                text_raw = output.read_bytes()
        # Preserve strings and duplicate keys while removing only JSONC comments and trailing commas.
        text = re.sub(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/',
                      lambda m: m[0] if m[0].startswith('"') else " " * len(m[0]), text_raw.decode("utf-8"))
        text = re.sub(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])',
                      lambda m: m[0] if m[0].startswith('"') else " " * len(m[0]), text)
        lock = json.loads(text, object_pairs_hook=unique_json_object, parse_constant=invalid_constant)
        if (not isinstance(lock, dict) or type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in {1, 2}
                or set(lock) - {"lockfileVersion", "configVersion", "workspaces", "packages"}
                or ("configVersion" in lock and (type(lock["configVersion"]) is not int or lock["configVersion"] not in {0, 1}))
                or not isinstance(lock.get("workspaces"), dict) or set(lock["workspaces"]) != {""}):
            return None
        root = lock["workspaces"][""]
        if (not isinstance(root, dict) or set(root) - {*fields, "name", "version"}
                or any(root.get(field, {}) != package.get(field, {}) for field in fields)
                or root.get("name") != package.get("name")
                or ("version" in root and root["version"] != package.get("version"))):
            return None
        packages = lock.get("packages")
        if not isinstance(packages, dict) or len(packages) >= MAX_PACKAGES:
            return None
        normalized = {"": package}
        for location, entry in packages.items():
            if not re.fullmatch(package_name + r"(?:/" + package_name + r")*", location):
                return None
            names = re.findall(r"@[^/]+/[^/]+|[^/]+", location)
            if (not isinstance(entry, list) or len(entry) != 4 or not isinstance(entry[0], str)
                    or not entry[0].startswith(names[-1] + "@") or entry[1] != "" or not isinstance(entry[2], dict)):
                return None
            version = entry[0][len(names[-1]) + 1:]
            if not re.fullmatch(exact_version, version):
                return None
            metadata = dict(entry[2])
            if set(metadata) - {*fields, "optionalPeers", "os", "cpu", "bin", "binDir", "license"}:
                return None
            optional_peers = metadata.pop("optionalPeers", [])
            if not isinstance(optional_peers, list) or any(not isinstance(name, str) or name not in metadata.get("peerDependencies", {}) for name in optional_peers):
                return None
            if optional_peers:
                metadata["peerDependenciesMeta"] = {name: {"optional": True} for name in optional_peers}
            for field in ("os", "cpu"):
                if isinstance(metadata.get(field), str):
                    metadata[field] = [metadata[field]]
            name = names[-1]
            normalized["node_modules/" + "/node_modules/".join(names)] = {
                **metadata, "version": version, "integrity": entry[3],
                "resolved": f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"}
        npm_lock = {"lockfileVersion": 3, "packages": normalized,
                    **{key: package[key] for key in ("name", "version") if key in package}}
        evidence = npm_source_declarations(repo, path, scope, lock_data=(raw, npm_lock))
        if evidence is not None:
            evidence.update(ecosystem="bun", lock_path=lock_path.relative_to(repo).as_posix(),
                            converted_sha256=sha256(text_raw))
        return evidence
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        return None


def source_license_documents(repo: Path, evidence: dict, manifest: dict, *, required: bool) -> bool:
    """Bind retained license documents to an exact npm name, version and integrity."""
    entries = manifest.get("dependency_licenses", {})
    source_files = {item["path"]: item["sha256"] for item in evidence["distribution_scope"].get("files", [])}
    for row in evidence["inventory"]:
        name = row["path"].rsplit("node_modules/", 1)[-1]
        entry = entries.get(f"npm:{name}@{row['version']}")
        if entry is None:
            if required and (not row["license"] or label_key(row["license"]) in HARMLESS_LICENSE_PLACEHOLDERS):
                return False
            continue
        if (not isinstance(entry, dict) or entry.get("version") != row["version"]
                or entry.get("integrity") != row["integrity"] or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("spdx"), str) or licence_expression_limited(entry["spdx"])):
            return False
        relative = Path(entry["path"])
        document = repo / relative
        if (relative.is_absolute() or ".." in relative.parts or relative.as_posix() != entry["path"]
                or any(p.is_symlink() for p in (document, *document.parents))
                or not document.is_file() or not licence_evidence_file(entry["path"])
                or document.stat().st_size > MAX_LICENSE_BYTES):
            return False
        raw = document.read_bytes()
        text = decode_licence(raw)
        if (sha256(raw) != entry.get("sha256") or entry["path"] not in source_files
                or source_files[entry["path"]] != entry["sha256"] or not readable_licence(text)):
            return False
        states = [licence_file_state(text), licence_expression(entry["spdx"])]
        if row["license"]:
            states.append(row["license_state"])
        row["license_document"] = entry
        row["license_state"] = next((s for s in ("strong", "proprietary", "unknown") if s in states), "accepted")
    return True


def root_licence(text: str) -> str | None:
    if licence_file_state(text) != "accepted":
        return None
    for identifier in ROOT_LICENSES:
        passages, digests = LICENSE_TEXTS[identifier]
        key = licence_text_key(text, root=identifier)
        if hashlib.sha256(key.encode()).hexdigest() in digests and all(licence_text_key(p) in key for p in passages):
            if identifier in NOTICE_LICENSES and not any(
                    re.fullmatch(COPYRIGHT_LINE, line.strip()) for line in licence_characters(text).splitlines()):
                return None
            return identifier
    return None


def license_audit(repo: Path, scanner: Scanner, manifest: dict) -> dict:
    candidates = [p for p in repo.iterdir() if p.name.upper() in ROOT_LICENSE_FILES]
    result = {"status": "blocked", "identifier": None, "dependencies": "not-verified"}
    if not candidates:
        scanner.add("tree", "license", "missing-license", "LICENSE")
        return result
    found = {}
    for candidate in candidates:
        text = decode_licence(candidate.read_bytes())
        found[candidate.name] = root_licence(text)
        if found[candidate.name] is None:
            scanner.add("tree", "license", "unrecognized-or-modified-license", candidate.name, value=text)
    identifiers = set(found.values())
    if len(identifiers) > 1 and None not in identifiers:
        for name in sorted(found)[1:]:
            scanner.add("tree", "license", "license-metadata-mismatch", name, value=found[name])
    if len(identifiers) == 1 and None not in identifiers:
        result.update(status="pass", identifier=identifiers.pop())
    project = {}
    if (repo / "pyproject.toml").exists():
        project = tomllib.loads((repo / "pyproject.toml").read_text()).get("project", {})
        declared = project.get("license")
        if declared is not None:
            matches = declared == result['identifier']
            if isinstance(declared, dict):
                if set(declared) == {'text'} and isinstance(declared['text'], str):
                    matches = result['identifier'] in {declared['text'], root_licence(declared['text'])}
                elif set(declared) == {'file'} and isinstance(declared['file'], str):
                    path = Path(declared['file'])
                    matches = (not path.is_absolute() and '..' not in path.parts
                               and (repo / path).is_file() and not (repo / path).is_symlink()
                               and root_licence(decode_licence((repo / path).read_bytes())) == result['identifier'])
            if not matches:
                scanner.add("tree", "license", "license-metadata-mismatch", "pyproject.toml", value=json.dumps(declared, sort_keys=True))
        if "dynamic" in project and any(x in project["dynamic"] for x in ("dependencies", "license")):
            scanner.add("tree", "license", "dynamic-license-or-dependencies", "pyproject.toml")
    packages, hooks, artifacts = node_packages(repo)
    package_free = bool(packages)
    source_scope = npm_source_scope(repo, manifest) if packages and artifacts and not hooks else None
    legacy_scope = npm_source_scope(repo, manifest, legacy_modes=True) if source_scope is not None else None
    source_reviews = []
    for path in packages:
        free = dependency_free_package(repo, path, scanner, result["identifier"])
        if not free or hooks or artifacts:
            package_free = False
            bun = any(path.with_name(name).exists() for name in ("bun.lock", "bun.lockb"))
            evidence = None
            if source_scope is not None:
                evidence = (bun_source_declarations if bun else npm_source_declarations)(repo, path, source_scope)
                try:
                    documents_valid = evidence is not None and source_license_documents(repo, evidence, manifest, required=bun)
                except (OSError, ValueError, TypeError, RecursionError):
                    documents_valid = False
                if not documents_valid:
                    evidence = None
            if evidence is None:
                scanner.add("tree", "license", "dependency-ecosystem-manual-review", path.relative_to(repo).as_posix())
            else:
                legacy = canonical_json({**evidence, "distribution_scope": legacy_scope}) if legacy_scope is not None else None
                finding = scanner.add("tree", "license", "bun-source-declarations-review" if bun else "npm-source-declarations-review", path.relative_to(repo).as_posix(),
                                      value=canonical_json(evidence), legacy_value=legacy)
                source_reviews.append({"path": scanner.safe_path(evidence["manifest_path"]),
                                       "fingerprint": finding["fingerprint"], "reviewed": finding["reviewed"],
                                       "package_count": len(evidence["inventory"]),
                                       "scope_fingerprint": fingerprint(canonical_json(source_scope)),
                                       "license_states": dict(Counter(row["license_state"] for row in evidence["inventory"]))})
    if source_reviews:
        result["npm_source_reviews"] = source_reviews
    if not packages:
        if artifacts and not hooks:
            scanner.add("tree", "license", "dependency-ecosystem-manual-review", "package.json")
        for path in hooks:
            scanner.add("tree", "license", "dependency-ecosystem-manual-review", path.relative_to(repo).as_posix())
    # Unknown ecosystems do not become a false green.
    for name in ("Cargo.toml", "go.mod", "pom.xml", "Gemfile", "composer.json", "build.gradle", "build.gradle.kts", "Package.swift", "environment.yml", "Pipfile", "setup.py", "setup.cfg"):
        if (repo / name).exists():
            scanner.add("tree", "license", "dependency-ecosystem-manual-review", name)
    for path in repo.glob("*.csproj"):
        scanner.add("tree", "license", "dependency-ecosystem-manual-review", path.name)
    if (repo / "pyproject.toml").exists() and "poetry" in tomllib.loads((repo / "pyproject.toml").read_text()).get("tool", {}):
        scanner.add("tree", "license", "dependency-ecosystem-manual-review", "pyproject.toml")
    for name in ("vendor", "vendored", "third_party", "third-party"):
        if (repo / name).is_dir():
            scanner.add("tree", "license", "vendored-attribution-review", name)
    deps = bool(project.get("dependencies") or project.get("optional-dependencies"))
    for path in repo.glob("*requirements*.txt"):
        if any(line.strip() and not line.lstrip().startswith("#") for line in path.read_text().splitlines()):
            deps = True
    if not deps and len(source_reviews) == len(packages) and source_reviews and all(r["reviewed"] for r in source_reviews):
        result["dependencies"] = "pass"
    if not deps and (not packages or package_free):
        result["dependencies"] = "none (package.json)" if package_free else "stdlib-only"
    # Attribution is never silently discarded, even when an export manifest excludes it.
    for rel in worktree_files(repo)[0]:
        if protected(rel) and excluded_path(rel, [*DEFAULT_EXCLUDES, *manifest["exclude"]]):
            scanner.add("tree", "license", "excluded-attribution", rel)
    return result


def quality_audit(repo: Path, scanner: Scanner, manifest: dict):
    tracked = {os.fsdecode(p) for p in git(repo, "ls-files", "-z").split(b"\0") if p}
    def shipped(rel: str) -> bool:
        return rel in tracked and (repo / rel).is_file()
    for name in REQUIRED_DOCUMENTS:
        if not shipped(name):
            scanner.add("tree", "quality", "missing-document", name)
    if not any(shipped(p.relative_to(repo).as_posix()) and not p.is_symlink()
               for directory, globs in issue_template_locations() for pattern in globs for p in (repo / directory).glob(pattern)):
        scanner.add("tree", "quality", "missing-issue-templates", ISSUE_TEMPLATE_DIR)
    readme = (repo / "README.md").read_text() if shipped("README.md") else ""
    if not re.search(r"^#+\s+.*(?:" + "|".join(map(re.escape, README_HEADINGS)) + ")", readme, re.I | re.M):
        scanner.add("tree", "quality", "missing-limitations", "README.md")
    if not any(shipped(p.relative_to(repo).as_posix()) for p in (repo / TEST_DIR).rglob(TEST_GLOB)):
        scanner.add("tree", "quality", "missing-tests", TEST_DIR)
    if not manifest["quickstart"]:
        scanner.add("tree", "quality", "quickstart-not-declared", "release-check.json")
    if not any(item.get("role") == "tests" for item in manifest["checks"]):
        scanner.add("tree", "quality", "test-command-not-declared", "release-check.json")
    config = tomllib.loads((repo / "pyproject.toml").read_text()).get("tool", {}) if (repo / "pyproject.toml").exists() else {}
    for name, role in CONFIGURED_CHECKS:
        if name in config and not any(item.get("role") == role for item in manifest["checks"]):
            scanner.add("tree", "quality", "configured-check-not-declared", "pyproject.toml", value=role)


def copy_tree(repo: Path, target: Path, manifest: dict, scanner: Scanner, *, allowlist: list[str] | None = None, commit: bool = True):
    if target.exists():
        explain("export destination already exists; choose a new path")
        raise AuditError("export-destination-exists")
    if target == repo or (repo in target.parents and allowlist is None):
        raise AuditError("export-inside-source")
    if target in repo.parents:
        raise AuditError("export-parent-of-source")
    target.mkdir(mode=0o700, parents=True)
    excluded = [*DEFAULT_EXCLUDES, *manifest["exclude"]]
    paths = []
    candidates, tracked = worktree_files(repo)
    if allowlist is not None:
        for rel in allowlist:
            path = Path(rel)
            if (not isinstance(rel, str) or path.is_absolute() or path.as_posix() != rel
                    or any(part in {".", "..", ".git"} for part in path.parts) or rel not in tracked):
                raise AuditError("allowlist-path")
            source = repo / rel
            if match_path(rel, manifest["exclude"]) or match_path(rel, DEFAULT_EXCLUDES) and not (
                    source.is_file() and not source.is_symlink() and blank_env_example(rel, source.read_bytes())):
                raise AuditError("allowlist-path")
            if (not source.is_file() or any(p.is_symlink() for p in (source, *source.parents))
                    or not source.resolve().is_relative_to(repo.resolve())):
                raise AuditError("allowlist-file")
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, dest)
            dest.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)
            paths.append(rel)
    else:
        for rel in candidates:
            rel = rel.rstrip("/")
            if excluded_path(rel, excluded):
                continue
            source = repo / rel
            if symlinked(repo, rel) or not source.is_file():
                scanner.add("export", "coverage", "unsupported-file", rel)
                continue
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, dest)
            dest.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)
            paths.append(rel)
    index_paths(target, paths, commit)


def index_paths(target: Path, paths: list[str], commit: bool = True):
    git(target, "init", "-q", "-b", "main")
    # Explicit paths only; no remote, hooks, original identity or original history.
    if paths:
        git(target, "--literal-pathspecs", "add", "-f", "--pathspec-from-file=-", "--pathspec-file-nul",
            input=b"".join(os.fsencode(path) + b"\0" for path in paths))
    if commit:
        git(target, "-c", "user.name=" + EXPORT_IDENTITY[0], "-c", "user.email=" + EXPORT_IDENTITY[1], "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Clean source export")


def preserve_historical_attribution(repo: Path, target: Path, report: dict, terms: list[str]):
    for commit in git(repo, "rev-list", "--all", "--reflog").splitlines():
        for entry in filter(None, git(repo, "ls-tree", "-r", "-z", commit.decode()).split(b"\0")):
            metadata, raw_path = entry.split(b"\t", 1)
            path = raw_path.decode("utf-8", "surrogateescape")
            if protected(path) and not (target / path).is_file():
                finding_scanner = Scanner(terms)
                finding_scanner.add("export", "license", "historical-attribution-missing", path, value=metadata)
                report["findings"].extend(finding_scanner.findings)
                report["counts"]["license"] = report["counts"].get("license", 0) + 1
            elif protected(path) and any(x in Path(path).name.upper() for x in ("NOTICE", "UPSTREAM")):
                oid = metadata.split()[2].decode()
                old_raw = git(repo, "cat-file", "blob", oid)
                old = re.sub(rb"\s+", b" ", old_raw).strip()
                current = re.sub(rb"\s+", b" ", (target / path).read_bytes()).strip()
                if any(re.sub(rb"\s+", b" ", line).strip() not in current for line in old_raw.splitlines() if line.strip()):
                    finding_scanner = Scanner(terms)
                    finding_scanner.add("export", "license", "historical-attribution-changed", path, value=old)
                    report["findings"].extend(finding_scanner.findings)
                    report["counts"]["license"] = report["counts"].get("license", 0) + 1


def safe_environment(home: Path, bin_dir: Path) -> dict:
    # Credentials, Git config, application caches and provider opt-ins do not inherit.
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    (home / "tmp").mkdir(mode=0o700, exist_ok=True)
    return {"TMPDIR": str(home / "tmp"), "HOME": str(home), "PATH": str(bin_dir) + os.pathsep + "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "XDG_CACHE_HOME": str(home / "cache"), "XDG_CONFIG_HOME": str(home / "config")}


def command(argv: list[str], cwd: Path, env: dict, timeout: int, stdin: bytes | None = None, digest=None) -> tuple[int, bytes]:
    # A timeout kills the process group, including any subprocess the test spawned.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as source:
        source.write(stdin or b"")
        source.seek(0)
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=None if stdin is None else source, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except PermissionError:
                process.kill()
            process.wait()
            code = 124
        output.seek(0)
        if digest is not None:
            for chunk in iter(lambda: output.read(1024 * 1024), b""):
                digest.update(chunk)
            output.seek(0)
        return code, output.read(8 * 1024 * 1024)


# Bounds apply before reading/serializing installed files, and again at ingestion.
MAX_LICENSE_BYTES = 256 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_PACKAGES = 2048
MAX_LICENSE_FILES = 256


def decode_licence(raw: bytes) -> str:
    """Choose byte order from BOMs or NUL lanes, never from printability."""
    encoding = "utf-8"
    for bom, encoding in ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
                          (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"),
                          (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            break
    else:
        encoding = "utf-8"
        if b"\0" in raw:
            # Licence prose is predominantly ASCII. Require a clear data lane
            # and predominantly zero high bytes; ambiguous patterns fail closed.
            def data_lane(width, offset):
                lanes = [raw[i::width] for i in range(width)]
                return all(lane and (lane.count(0) / len(lane) < .2 if i == offset
                                     else lane.count(0) / len(lane) > .8)
                           for i, lane in enumerate(lanes))
            encodings = [name for width in (4, 2) for offset, name in
                         ((0, f"utf-{width * 8}-le"), (width - 1, f"utf-{width * 8}-be"))
                         if data_lane(width, offset)]
            if len(encodings) != 1:
                return "\ufffd" + raw.decode("utf-8", errors="replace")
            encoding = encodings[0]
    try:
        text = raw.decode(encoding)
        if not any(not c.isprintable() and c not in "\n\r\t\f" and unicodedata.category(c) != 'Cf' for c in text):
            return text
    except UnicodeError:
        pass
    # Preserve readable restrictions, but mark every uncertain/corrupt decode.
    # readable_licence rejects this marker, so digest evidence cannot waive it.
    return "\ufffd" + raw.decode(encoding, errors="replace")


def licence_candidate(path: str, declared: bool = False) -> bool:
    parts = Path(path).parts
    name = Path(path).name
    return (declared or bool(re.fullmatch(DEPENDENCY_LICENSE_FILE, name, re.I))
            or any(p.casefold() in {"licenses", "licences"} for p in parts[:-1])
            or bool(re.fullmatch(r"(?:MIT|MIT-0|BSD(?:-[234]-Clause)?|ISC|Apache-2\.0|Zlib|Unlicense|CC0-1\.0|BSL-1\.0|PSF-2\.0|[AL]?GPL(?:-[0-9.]+(?:-only|-or-later)?)?|MPL(?:-[0-9.]+)?|EPL(?:-[0-9.]+)?)(?:\.(?:txt|md|rst))?", name, re.I)))


METADATA_SCRIPT = ('import importlib.metadata as m, json, re, hashlib, csv, unicodedata\nfrom pathlib import Path\n'
                   + 'MAX_LICENSE_BYTES=' + str(MAX_LICENSE_BYTES) + '\n'
                   + 'MAX_METADATA_BYTES=' + str(MAX_METADATA_BYTES) + '\n'
                   + 'MAX_PACKAGES=' + str(MAX_PACKAGES) + '\n'
                   + 'MAX_LICENSE_FILES=' + str(MAX_LICENSE_FILES) + '\n'
                   + inspect.getsource(decode_licence) + inspect.getsource(licence_candidate).replace('DEPENDENCY_LICENSE_FILE', repr(DEPENDENCY_LICENSE_FILE)) + '''
def declared(d,p):
 return any(str(p)==f or str(p).endswith('/'+f) for f in d.metadata.get_all('License-File',[]))
out=[]
total=0
for d in m.distributions():
 if (d.metadata.get('Name') or '').lower() in {'pip','setuptools'}: continue
 files=[]
 file_bytes=0
 limited=False
 # Read RECORD directly: recent importlib versions silently drop missing files.
 record_text=d.read_text('RECORD')
 if record_text is not None:
  rows=list(csv.reader(record_text.splitlines()))
  records=[Path(row[0]) for row in rows if row and row[0]]
  invalid=not records or any(len(row)!=3 or not row[0] for row in rows)
 else:
  records=d.files
  invalid=not records
 metadata=d.metadata
 if metadata.defects or any(len(metadata.get_all(key,[]))!=1 for key in ('Name','Version')): invalid=True
 # A licence present inside dist-info but omitted from RECORD is also a gap.
 metadata_path=getattr(d,'_path',None)
 if isinstance(metadata_path,Path) and metadata_path.is_dir():
  recorded={d.locate_file(p) for p in (records or [])}
  if any(licence_candidate(str(p.relative_to(metadata_path))) and p not in recorded for p in metadata_path.rglob('*') if p.is_file() or p.is_symlink()): invalid=True
 declarations=d.metadata.get_all('License-File',[])
 if any(not f.strip() or not any(str(p)==f or str(p).endswith('/'+f) for p in (records or [])) for f in declarations): invalid=True
 for p in (records or []):
  if not licence_candidate(str(p),declared(d,p)): continue
  path=d.locate_file(p)
  if not path.is_file() or path.is_symlink():
   invalid=True
   continue
  if len(files)>=MAX_LICENSE_FILES or path.stat().st_size>MAX_LICENSE_BYTES:
   limited=True
   break
  with path.open('rb') as handle: raw=handle.read(MAX_LICENSE_BYTES+1)
  if len(raw)>MAX_LICENSE_BYTES:
   limited=True
   break
  entry={'path':str(p),'hash':hashlib.sha256(raw).hexdigest(),'text':decode_licence(raw),'declared':declared(d,p)}
  file_bytes+=len(json.dumps(entry).encode())
  if total+file_bytes>MAX_METADATA_BYTES:
   limited=True
   break
  files.append(entry)
 item={'name':d.metadata.get('Name'), 'version':d.version,
 'expression':d.metadata.get('License-Expression'), 'license':d.metadata.get('License'),
 'expressions':d.metadata.get_all('License-Expression',[]), 'licenses':d.metadata.get_all('License',[]),
 'classifiers':d.metadata.get_all('Classifier',[]), 'license_files':files}
 if limited: item['metadata_limit']=True
 if invalid: item['metadata_invalid']=True
 total+=len(json.dumps(item).encode())
 if len(out)>=MAX_PACKAGES or total>MAX_METADATA_BYTES:
  out=[{'metadata_limit':True}]
  break
 out.append(item)
print(json.dumps(out))''')

# Widely used permissive identifiers; weak copyleft follows the recorded policy.
COMPATIBLE = {"MIT", "MIT-0", "Apache-2.0", "BSD", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "ISC", "Zlib", "PSF-2.0", "0BSD", "Unlicense", "CC0-1.0", "Python-2.0", "BSL-1.0", "NCSA", "HPND", "X11", "WTFPL"}
SPDX_OPERATORS = r"(?<![\w.-])(?:AND|OR)(?![\w.-])"
# Full matches only. Trove prefixes are validated separately, never discarded.
CLASSIFIERS = {
    "MIT License": "MIT", "MIT No Attribution License (MIT-0)": "MIT-0",
    "Apache Software License": "Apache-2.0", "BSD License": "BSD",
    "ISC License (ISCL)": "ISC", "Python Software Foundation License": "PSF-2.0",
    "zlib/libpng License": "Zlib", "The Unlicense (Unlicense)": "Unlicense",
    "Boost Software License 1.0 (BSL-1.0)": "BSL-1.0",
    "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication": "CC0-1.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Eclipse Public License 2.0 (EPL-2.0)": "EPL-2.0",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "GNU Library or Lesser General Public License (LGPL)": "LGPL",
}

# Normalise visual separators, not arbitrary suffixes. Unknown full labels block.
LOOKALIKES = str.maketrans(dict(zip(
    "АВЕІЈКМНОРСТХаеіјорсхуΑΒΕΖΗΙΚΜΝΟΡΤΥΧαεικνορτυх",
    "ABEIJKMHOPCTXaeijopcyyABEZHIKMNOPTYXaeikvoptyx")))


def licence_characters(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(LOOKALIKES)
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def label_key(text: str) -> str:
    # Keep word boundaries, parentheses and expression operators distinct.
    text = licence_characters(text).casefold()
    text = re.sub(r"(?<=[a-z])(?:[.\-]\s*)+(?=[a-z])", "", text)
    return re.sub(r"\s+", " ", text).strip()


LABELS = {label_key(x): "accepted" for x in COMPATIBLE}
for base in ("LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0"):
    for suffix in ("", "-only", "-or-later", "+"):
        LABELS[label_key(base + suffix)] = "accepted"
for name in CLASSIFIERS:
    LABELS[label_key(name)] = "accepted"
for name in (
    "MIT License", "The MIT License", "The MIT License (MIT)", "MIT Software License",
    "Expat", "Expat (MIT/X11)", "MIT/X11", "Apache Software License",
    "Apache License, Version 2.0", "Apache License 2.0", "Apache 2.0",
    "BSD License", "BSD 2-Clause", "BSD 2-Clause License", "BSD 3-Clause",
    "BSD 3-Clause License", "BSD 4-Clause License", "New BSD License", "Modified BSD License",
    "Public Domain", "CC0 1.0 Universal", "ISC License", "Zlib License", "Zlib/libpng License",
    "LGPL", "LGPL v3", "LGPLv2", "LGPLv2.1", "LGPLv3", "LGPLv3+", "LGPLv2+",
    "GNU Library General Public License", "GNU Lesser General Public License",
    "MPL", "EPL", "Eclipse Public License 2.0", "Eclipse Public License 1.0",
    "GNU Lesser General Public License v3", "GNU Lesser General Public License v2.1",
    "GNU Lesser General Public License v2 or later (LGPLv2+)",
):
    LABELS[label_key(name)] = "accepted"
for base in ("GPL", "AGPL", "GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-3.0"):
    for suffix in ("", "-only", "-or-later", "+"):
        LABELS[label_key(base + suffix)] = "strong"
for name in ("GPLv2", "GPLv3", "GPLv2+", "GPLv3+", "GPL 3", "GPL3+", "GPL3", "GPL_v3",
             "AGPLv3", "GNU GPL v3", "GNU General Public License", "General Public Licence",
             "GNU Affero General Public License", "GNU Affero General Public License v3",
             "GNU General Public License v2 (GPLv2)", "GNU General Public License v3 (GPLv3)",
             "GNU General Public License v2 or later (GPLv2+)", "GNU General Public License v3 or later (GPLv3+)",
             "GNU Affero General Public License v3 or later (AGPLv3+)", "GNU Affero General Public License v3 (AGPLv3)"):
    LABELS[label_key(name)] = "strong"
for name in ("Proprietary", "Other/Proprietary License", "Commercial", "Free For Home Use",
             "Elastic License 2.0", "BUSL-1.1", "CC-BY-NC-SA-4.0", "CC-BY-NC", "Commons Clause",
             "All Rights Reserved", "Internal use only", "For internal use only",
             "Polyform Noncommercial", "SSPL", "SSPL-1.0", "Server Side Public License"):
    LABELS[label_key(name)] = "proprietary"

# These mean no assertion, never acceptance; another source must establish it.
HARMLESS_LICENSE_PLACEHOLDERS = {"unknown", "none", "noassertion", "dual license"}


def strong_licence(text: str) -> bool:
    # Only used on evidence that has FAILED complete-text recognition. Thus a
    # recognised LGPL/MPL text quoting GPL is never confused with a GPL grant.
    prose = label_key(text)
    compact = re.sub(r"[^a-z0-9]", "", licence_characters(text).casefold())
    return any(part in compact for part in ("gnugeneralpubliclicense", "gnugeneralpubliclicence",
        "gnuafferogeneralpubliclicense", "gnuafferogeneralpubliclicence", "gnupubliclicense", "gnupubliclicence")) or bool(
        re.search(r"(?<![a-z])a?g[.\-\s]*p[.\-\s]*l(?:[_ -]?v?[_ -]?\d|\b)",
                  licence_characters(text).casefold())) or bool(
        re.search(r'(?<!lesser )(?<!library )\bgeneral public licen[cs]e\b', prose))


def proprietary_licence(text: str) -> bool:
    key = label_key(text)
    prose = re.sub(r"\s+", " ", licence_characters(text).casefold())
    return (any(re.search(r'(?<!\w)' + re.escape(label) + r'(?!\w)', key)
                for label, state in LABELS.items() if state == 'proprietary')
            or bool(re.search(r"\b(?:proprietary|non[- ]?commercial|no redistribution|"
                              r"redistribution (?:of this software )?is prohibited|"
                              r"internal use only|server side public licen[cs]e|sspl)\b", prose)))


def licence_atom(label: str) -> str:
    return LABELS.get(label_key(label), "unknown")


def licence_restriction(text: str) -> str:
    """An unsuccessful parse must retain stronger assertions in its input."""
    return 'strong' if strong_licence(text) else 'proprietary' if proprietary_licence(text) else 'unknown'


def licence_classifier(label: str) -> str | None:
    parts = [p.strip() for p in licence_characters(label).split("::")]
    if not parts or parts[0].casefold() != "license":
        return "unknown"
    if [p.casefold() for p in parts] == ['license', 'osi approved']:
        return None  # a neutral parent category, never an acceptance assertion
    ending = " :: ".join(parts[1:])
    prefix = "OSI Approved :: "
    if ending.startswith(prefix):
        state = licence_atom(ending[len(prefix):])
    else:
        state = licence_atom(ending)
    # Accepted legacy two-part licence classifiers are still full table matches.
    return licence_restriction(label) if state == 'unknown' else state


LICENSE_EXCEPTIONS = {"classpath-exception-2.0", "llvm-exception"}


def licence_evidence_file(path: str, declared: bool = False) -> bool:
    return (not re.fullmatch(r"NOTICE.*", Path(path).name, re.I)
            and Path(path).suffix.casefold() in {"", ".txt", ".md", ".mdx", ".rst", ".mit", ".bsd", ".apache", ".isc", ".gpl", ".agpl", ".lgpl", ".mpl", ".epl"}
            and licence_candidate(path, declared))


def licence_expression_limited(label: str) -> bool:
    return len(label) > 8192 or label.count('(') > 64


def licence_expression(label: str) -> str:
    """Within a valid choice OR needs one branch; independent sources still win."""
    if licence_expression_limited(label):
        return licence_restriction(label)
    atom = licence_atom(label)
    operators = SPDX_OPERATORS + r"|(?<![\w.-])WITH(?![\w.-])"
    if atom == "accepted" or atom != "unknown" and not re.search(operators, label, re.I):
        return atom
    tokens = [t.strip() for t in re.split(r"(\(|\)|" + SPDX_OPERATORS + ")", label, flags=re.I) if t.strip()]
    position = 0

    def parse_identifier(token):
        state = licence_atom(token)
        if state == "unknown" and not re.fullmatch(r"LicenseRef-[A-Za-z0-9.-]+", token, re.I):
            raise ValueError
        if state in {"strong", "proprietary"} and not re.fullmatch(r"(?:a?gpl)(?:[ _-]?v?[_ -]?\d+(?:\.\d+)*(?:-only|-or-later|\+)?)?|(?:gnu )?(?:affero )?general public licen[cs]e(?: (?:v|version )?[0-9.]+(?: or later)?)?(?: \((?:a?gpl)[0-9v.+-]*\))?", token, re.I):
            raise ValueError
        return state

    def parse_atom():
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token == "(":
            state = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
            return state
        if token.upper() in {"AND", "OR", ")"}:
            raise ValueError
        parts = re.split(r"(?<![\w.-])WITH(?![\w.-])", token, flags=re.I)
        if len(parts) == 2:
            base = parse_identifier(parts[0].strip())
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", parts[1].strip()):
                raise ValueError
            if base != "unknown" and parts[1].strip().casefold() in LICENSE_EXCEPTIONS:
                return base
            return base if base in {"strong", "proprietary"} else "unknown"
        if len(parts) != 1:
            raise ValueError
        return parse_identifier(token)

    def parse_and():
        nonlocal position
        state = parse_atom()
        while position < len(tokens) and tokens[position].upper() == "AND":
            position += 1
            other = parse_atom()
            state = next((s for s in ("strong", "proprietary", "unknown") if s in (state, other)), "accepted")
        return state

    def parse_or():
        nonlocal position
        state = parse_and()
        while position < len(tokens) and tokens[position].upper() == "OR":
            position += 1
            other = parse_and()
            state = "accepted" if "accepted" in (state, other) else next((s for s in ("strong", "proprietary", "unknown") if s in (state, other)))
        return state

    try:
        state = parse_or()
        # Unknown references/exceptions can themselves contain stronger evidence.
        return state if position == len(tokens) and state != 'unknown' else licence_restriction(label)
    except (ValueError, RecursionError):
        return licence_restriction(label)


# Whole-text digests are fingerprints of canonical normative text, not a cache
# learned from the package being audited. Short passages identify the candidate;
# its full digest accounts for every remaining meaningful character.
LICENSE_TEXTS = {
    'MIT': (('permission is hereby granted free of charge', 'subject to the following conditions', 'the above copyright notice and this permission notice'), ['81a61d35f6891e560d80c95e831624d3270eb7ccf5f492522851169cb355ddab']),
    'MIT-0': (('permission is hereby granted free of charge', 'to permit persons to whom the software is furnished to do so', 'authors or copyright holders be liable'), ['9dde5a381a6884c081965fac48c212c08192ff93173adbaa496985824107f58a']),
    'BSD-2-Clause': (('redistribution and use in source and binary forms', 'redistributions of source code must retain', 'redistributions in binary form must reproduce'), ['1328f1513430d5690e86eb9a63ac9031702d4570f7d910e9be7c7046cb091c85', '73df6017d799dcaf80d531190070f97c3a5a100e92b0646fe6829d12293241bb']),
    'BSD-3-Clause': (('redistribution and use in source and binary forms', 'neither the name', 'without specific prior written permission'), ['fad79cba3e77e83e69641bd7d3dd8ee15938439023e379b5bbcc829d32bb49d3', 'efb4863361df74d33da13e27f030067844f7b8bad1115f1d2f9ad6bb870370c6']),
    'ISC': (('permission to use copy modify andor distribute this software', 'for any purpose with or without fee', 'the author disclaims all warranties'), ['2ca2d1ff4c9cab1849313ddab628dd0788dbfa472a7dd51d27c021daa6aa3d2e', '513c8bf5ea4b9d31dc7c1d5e612891fa487b66584e78166eed33729a0e421aef']),
    'Apache-2.0': (('grant of copyright license', 'grant of patent license', 'commercial damages or losses'), ['9385e77162734bf297f30f924cb02e25e9b96adc73405f38cf55279760020177', 'ebfb9839bd55fb97095d377ca4adb8514fee4dd44a98ccbe2a8b430b3fe605f5']),
    'Zlib': (('the origin of this software must not be misrepresented', 'altered source versions must be plainly marked', 'this notice may not be removed or altered'), ['bea003f54e548bce073823f937798022b5d2bfe0c152d363e2b62c3b40d8ad73']),
    'Unlicense': (('this is free and unencumbered software released into the public domain', 'relinquishment in perpetuity', 'detriment of our heirs and successors'), ['bb28cc84551e602fa595813d0910e669c92cf2465e9b1bdc916144ab8bc37666']),
    'CC0-1.0': (('waiver', 'public license fallback', 'limitations and disclaimers'), ['a1c5451395262a9c57097cf8ed1be6259bce24f74691c20b350916c920658336']),
    'MPL-2.0': (('each contributor hereby grants', 'incompatible with secondary licenses', 'if you initiate litigation against any entity'), ['b203b68ce18fc8813145291e137d23b974d9d04de13b0366be0bb4431a2d1cb1']),
    'LGPL-2.1': (('this license the lesser general public license', 'you must cause the whole of the work to be licensed', 'as a consequence of a court judgment'), ['4dbd050ce7b4900cd3dcd7afbd0ac8785c7f54aba832e515e3002c23d3d0a965']),
    'LGPL-3.0': (('this version of the gnu lesser general public license incorporates', 'recombine or relink the application', 'use a suitable shared library mechanism'), ['be266b3e6b95a63311f981209450506637ec6eb6c4859e4c761c158ded39a699']),
    'GPL-2.0': (('gnu general public license', 'you must cause any work that you distribute or publish', 'no warranty'), ['d10b192c1f24c2580f4f91ac32263c90fea0c6a00c0dbc5305fbd0ec3d7522b0']),
    'GPL-3.0': (('gnu general public license', 'protecting users legal rights from anticircumvention law', 'no surrender of others freedom'), ['d0ae9f8a0066fc711eece17ebee94b45e4b5d0010f1613115eac1b83b161051f']),
    'BSL-1.0': (('to use reproduce display distribute execute and transmit', 'machineexecutable object code generated by', 'title and noninfringement'), ['3e92e670923680267ede2c7222e5cd6f7c2e495d94278af51c90425717d26551']),
    'PSF-2.0': (('python software foundation', 'worldwide license to reproduce analyze test', 'relationship of agency partnership or joint venture'), ['2366c0b8707a123d4de87ccc1a0c859aabcd37d4f5bab83eff1364a23f202ffe']),
}


HOLDER_WORD = r"(?:[A-Z][\w'-]*(?:\.)?|and|of|the|contributors|individual)"
COPYRIGHT_LINE = (r"Copyright\s*(?:\([cC]\)|©)?\s*(?:[0-9]{4}(?:[ ,\-–]+[0-9]{4})*[, ]*)?"
                  + HOLDER_WORD + r"(?:[ ]+" + HOLDER_WORD + r"){0,15}\.?(?:[ \t]+All rights reserved\.)?[ \t]*")


def licence_text_key(text: str, *, root: str | None = None) -> str:
    text = licence_characters(text)
    # Only ordinary standalone copyright headers are variable. A prose suffix,
    # extra sentence, or restriction is retained and invalidates the full digest.
    def alnum(value):
        return "".join(c for c in value.casefold() if c.isalnum())
    lines = text.splitlines()
    prefix = True
    saw_copyright = False
    kept = []
    for line in lines:
        stripped = line.strip()
        if root == "MIT":
            heading = bool(re.fullmatch(r"(?:The )?MIT(?: (?:Software )?License)?(?: \(MIT\))?", stripped, re.I))
        else:
            heading = licence_atom(stripped) == "accepted" and (
                not root or alnum(stripped) in {alnum(root), alnum(root) + "license"})
        if prefix and (not stripped or re.fullmatch(r"[-=_]+", stripped) or heading):
            continue
        if prefix and re.fullmatch(COPYRIGHT_LINE, stripped) and licence_restriction(stripped) == 'unknown':
            saw_copyright = True
            continue
        if prefix and saw_copyright and stripped.casefold() == "all rights reserved.":
            continue
        if stripped:
            prefix = False
        kept.append(line)
    # Case, punctuation, quotes, whitespace and hyphenation are irrelevant to
    # identification. Letters/digits and their order remain fully accounted for.
    return "".join(c for c in "\n".join(kept).casefold() if c.isalnum())


def intact_licence_text(text: str) -> bool:
    return "\ufffd" not in text and not any(
        not c.isprintable() and c not in "\n\r\t\f" and unicodedata.category(c) != "Cf" for c in text)


def readable_licence(text: str) -> bool:
    return bool(text.strip()) and intact_licence_text(text)


def licence_file_state(text: str) -> str:
    if len(text.encode('utf-8')) > MAX_LICENSE_BYTES:
        return "unknown"
    if not readable_licence(text):
        return licence_restriction(text)
    declarations = re.findall(r"^[ \t]*SPDX-License-Identifier:[ \t]*([^\r\n]+)$", text, re.I | re.M)
    body = re.sub(r"^[ \t]*SPDX-License-Identifier:[^\r\n]*", "", text, flags=re.I | re.M)
    declaration_states = [licence_expression(d) for d in declarations]
    key = licence_text_key(body)
    digest = hashlib.sha256(key.encode()).hexdigest()
    text_state = "unknown"
    for identifier, (passages, digests) in LICENSE_TEXTS.items():
        if digest in digests and all(licence_text_key(p) in key for p in passages):
            text_state = "strong" if identifier.startswith(("GPL-", "AGPL-")) else "accepted"
            break
    if not body.strip() and declarations:
        text_state = "accepted"  # a complete SPDX-only declaration, no stray body
    if text_state == "unknown" and strong_licence(body):
        text_state = "strong"
    if text_state == "unknown" and proprietary_licence(body):
        text_state = "proprietary"
    states = [text_state, *declaration_states]
    return next((state for state in ("strong", "proprietary", "unknown") if state in states), "accepted")


def valid_dependency_metadata(package) -> bool:
    if not isinstance(package, dict):
        return False
    if any(not isinstance(package.get(key), str) or not package[key].strip() for key in ("name", "version")):
        return False
    if any(package.get(key) is not None and not isinstance(package[key], str) for key in ("expression", "license")):
        return False
    if any(not isinstance(package.get(key, []), list) or any(not isinstance(value, str) for value in package.get(key, []))
           for key in ("expressions", "licenses", "classifiers")):
        return False
    values = [package['name'], package['version'], package.get('expression') or '', package.get('license') or '',
              *package.get('expressions', []), *package.get('licenses', []), *package.get('classifiers', [])]
    if any(not intact_licence_text(value) for value in values):
        return False
    files = package.get("license_files")
    return isinstance(files, list) and all(
        isinstance(f, dict) and isinstance(f.get("path"), str) and bool(f["path"])
        and isinstance(f.get("hash"), str) and bool(re.fullmatch(r"[a-f0-9]{64}", f["hash"]))
        and isinstance(f.get("text"), str) and isinstance(f.get("declared", False), bool)
        for f in files)


def dependency_audit(raw: bytes, repo: Path, scanner: Scanner, manifest: dict) -> dict:
    def limit():
        scanner.add("verification", "coverage", "dependency-metadata-limit", "@dependencies")
    if len(raw) > MAX_METADATA_BYTES:
        limit()
        return {"packages": 0, "blocked": 1, "accepted_on_license_file": []}
    def invalid():
        scanner.add("verification", "coverage", "dependency-metadata-invalid", "@dependencies")
        return {"packages": 0, "blocked": 1, "accepted_on_license_file": []}
    try:
        packages = json.loads(raw, object_pairs_hook=unique_json_object)
    except (ValueError, RecursionError):
        return invalid()
    if not isinstance(packages, list):
        return invalid()
    if len(packages) > MAX_PACKAGES:
        limit()
        return {"packages": len(packages), "blocked": 1, "accepted_on_license_file": []}
    count, accepted_files = 0, []
    for package in packages:
        if not isinstance(package, dict):
            return invalid()
        if package.get('metadata_invalid'):
            return invalid()
        if package.get("metadata_limit"):
            limit()
            count += 1
            continue
        if not valid_dependency_metadata(package):
            return invalid()
        name = package["name"]
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        expressions = [package.get("expression") or "", *package.get("expressions", [])]
        legacy = [package.get("license") or "", *package.get("licenses", [])]
        if any(licence_expression_limited(value) for value in expressions) or any(
                len(value.encode()) > MAX_LICENSE_BYTES for value in legacy):
            limit()
            count += 1
            continue
        states = [licence_expression(value) for value in expressions
                  if value.strip() and label_key(value) not in HARMLESS_LICENSE_PLACEHOLDERS]
        for value in legacy:
            if not value.strip() or label_key(value) in HARMLESS_LICENSE_PLACEHOLDERS:
                continue
            state = licence_expression(value)
            if state != 'accepted':
                text_state = licence_file_state(value)
                # Complete canonical LGPL/MPL text may legitimately quote GPL.
                # Declarations/restrictions still prevent full-text acceptance.
                state = ('accepted' if text_state == 'accepted' else
                         next((s for s in ('strong', 'proprietary', 'unknown') if s in (state, text_state))))
            states.append(state)
        states += [state for c in package.get("classifiers", [])
                   if licence_characters(c).strip().casefold().startswith("license")
                   if (state := licence_classifier(c)) is not None]
        files = package["license_files"]
        if (len(files) > MAX_LICENSE_FILES or any(len(f['text'].encode()) > MAX_LICENSE_BYTES for f in files)
                or any(licence_expression_limited(d) for f in files for d in
                       re.findall(r'^[ \t]*SPDX-License-Identifier:[ \t]*([^\r\n]+)$', f['text'], re.I | re.M))):
            limit()
            count += 1
            continue
        licence_files = [f for f in files if licence_evidence_file(f["path"], f.get("declared", False))]
        file_states = []
        for f in files:
            state = licence_file_state(f.get("text", ""))
            file_states.append("unknown" if state == "accepted" and f not in licence_files else state)
        all_states = [*states, *file_states]
        state = next((s for s in ("strong", "proprietary", "unknown") if s in all_states),
                     "accepted" if "accepted" in all_states else "unknown")
        if state == "accepted" and not any(s == "accepted" for s in states):
            accepted_files.append(scanner.safe_path("@dependency/" + name))
        entries = [value for key, value in manifest.get('dependency_licenses', {}).items()
                   if re.sub(r'[-_.]+', '-', key).lower() == normalized]
        if len(entries) > 1:
            return invalid()  # aliases must not select weaker evidence by ordering
        evidence = entries[0] if entries else None
        evidence_bound = (isinstance(evidence, dict)
                          and evidence.get("version") == package["version"]
                          and isinstance(evidence.get("sha256"), str)
                          and bool(re.fullmatch(r"[a-f0-9]{64}", evidence["sha256"]))
                          and any(evidence["sha256"] == f["hash"] for f in licence_files))
        if evidence_bound:
            if not isinstance(evidence.get('spdx', ''), str):
                return invalid()
            if licence_expression_limited(evidence.get('spdx', '')):
                limit()
                count += 1
                continue
        evidence_state = licence_expression(evidence.get("spdx", "")) if evidence_bound else None
        # Supplied evidence can add a blocker but cannot lower a package's own
        # strong/proprietary state. An accepted resolution stays a visible review.
        if state not in {"strong", "proprietary"} and evidence_state in {"strong", "proprietary", "unknown"}:
            state = evidence_state
        evidence_review = (state == "unknown" and evidence_state == "accepted"
                           and all(file_state != 'unknown' or
                                   (f in licence_files and readable_licence(f['text'])
                                    and f['hash'] == evidence['sha256'])
                                   for f, file_state in zip(files, file_states)))
        if state != "accepted":
            bound = {**package, "license_files": [{k: v for k, v in f.items() if k != "text"} for f in files]}
            if evidence is not None:
                bound["dependency_license_evidence"] = evidence
            finding = scanner.add("verification", "license", "dependency-license-review", "@dependency/" + name,
                                  value=json.dumps(bound, sort_keys=True),
                                  details={"reviewed": True, "review_source": "dependency_licenses"} if evidence_review else None)
            count += not finding["reviewed"]
    return {"packages": len(packages), "blocked": count, "accepted_on_license_file": accepted_files}


def requirements_text() -> str:
    example = {
        "exclude": [], "approvals": [{"scope": "verification", "kind": "dependency-license-review", "path": "@dependency/example", "fingerprint": "0123456789abcdef", "reason": "Reviewed the exact installed licence evidence and accepted it."}],
        "quickstart": [{"file": "README.md", "line": 3, "argv": ["python", "-m", "pip", "install", "."]}],
        "checks": [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}],
        "dependency_licenses": {"example": {"version": "1.0", "spdx": "MIT", "sha256": "0" * 64}}
    }
    return "\n".join([
        "Release requirements (no repository needed):",
        "Root licence: one of " + ", ".join(ROOT_LICENSE_FILES) + " (case insensitive); standard unmodified MIT grant/disclaimer. Other licences need manual review.",
        "Required root documents: " + ", ".join(REQUIRED_DOCUMENTS) + ".",
        "README.md Markdown heading containing (case insensitive): " + ", ".join(README_HEADINGS) + ".",
        "Issue template: a tracked, non-symlink file in " + "; ".join(directory + "/ matching " + " or ".join(globs) for directory, globs in issue_template_locations()) + ".",
        "Tests: at least one " + TEST_DIR + "/" + TEST_GLOB + " (subdirectories allowed).",
        "release-check.json keys: " + ", ".join(MANIFEST_KEYS) + ". license is a legacy optional field, not an override.",
        "exclude: relative path/glob strings; attribution must be preserved. approvals: objects with scope, kind, path, fingerprint.",
        "Denylist hits require exact owner approval; secrets cannot be waived.",
        "Alphabetic private terms: case-insensitive whole words/components block; substrings confined to one longer Unicode letter component are reviewable, not blockers. Punctuation, digits, underscores and camelCase/acronym transitions delimit components. Adjacent combining marks, invisible format characters or decoding replacements, matches crossing case transitions, and ambiguous uppercase-acronym/lowercase joins stay blocking. Other terms keep literal matching, with the existing short-alphanumeric alias boundaries.",
        "Dependency approvals also require a nonempty reason. Copy scope, kind, path and fingerprint from the report; the fingerprint binds name, exact version, metadata, all licence-file hashes and any supplied dependency_licenses entry. Stale reviews stop applying; reviewed findings remain visible.",
        "quickstart: nonempty entries with file, one-based line, argv (a nonempty string array); the documentation line must shell-split to exactly argv.",
        "checks: nonempty entries with argv; at least one role=tests. Accepted roles: " + ", ".join(CHECK_ROLES) + ".",
        "quickstart and checks entries take an optional \"timeout\": whole seconds greater than 0 for that command, instead of --timeout. A command that runs past its limit fails with command-timeout.",
        "verify_tools: optional list of at most 8 distinct bare executable names matching ^[A-Za-z0-9._+-]+$ (excluding . and ..). Only absolute caller PATH entries are searched; relative and empty entries are ignored. Regular executable targets must resolve outside the audited repository, original source, reports and export. Missing, unsafe or conflicting tools block verification. The caller's PATH and environment are not inherited.",
        "Configured checks: " + ", ".join(name + " requires role=" + role for name, role in CONFIGURED_CHECKS) + ".",
        "dependency_licenses: normalized package-name keys with exact version, spdx expression, sha256 (full installed licence-document digest); existing lowercase-name keys also work, but conflicting aliases block coverage. Resolutions remain visible as reviewed findings; evidence cannot erase GPL/AGPL or proprietary indications, even after parsing fails, or waive another unknown file. Empty/corrupt/binary files cannot supply resolutions.",
        "Recognised permissive identifiers: " + ", ".join(sorted(COMPATIBLE)) + ". Human-readable metadata/classifiers are also recognised.",
        "Unlabelled file evidence: plain document named LICENSE/LICENCE, COPYING, COPYRIGHT or UNLICENSE, a licence identifier such as GPL-3.0.txt, a file under licenses/licences, or a document declared by License-File metadata. Complete recognised text or an SPDX-only declaration is required. Empty/binary, source and markup files do not qualify. NOTICE alone is not a licence file: NOTICE files are scanned for assertions but cannot establish acceptance or supply digest evidence, even if declared by License-File.",
        "Dependency policy: recognised permissive and weak copyleft accepted; GPL/AGPL or proprietary indications from independent sources win. Unknown licences need review. Unlabelled packages need recognizable permissive/weak-copyleft text or valid SPDX declarations. OR needs an acceptable branch; otherwise stronger indications survive. AND needs every part acceptable. License :: OSI Approved alone is neutral. Missing inventory/files, corrupt metadata, malformed headers and duplicate JSON keys block coverage.",
        "Example manifest for your own repository (assumes its README line 3 is: python -m pip install .; adjust file, line and argv to match your documentation):",
        json.dumps(example, indent=2),
        "Passing also requires an external denylist, complete local history and attribution, no unresolved personal/secret/path/hostname/email/media/metadata findings, and --verify in a fresh clone/venv/HOME. Install the project and test tools through declared commands. Export rescans a clean one-commit copy; nothing is published."
    ]) + "\n"


def venv_failure(output: bytes, scanner: Scanner, ensurepip_missing: bool = False) -> dict:
    text = output.decode("utf-8", errors="replace")
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    normalized = " ".join(text.split())
    missing = ensurepip_missing or bool(re.search(r"ensurepip (?:is not available|is missing)|No module named ['\"]?ensurepip|cannot import (?:name )?['\"]?ensurepip", normalized, re.I))
    if missing:
        return {"cause": "missing-ensurepip", "message": f"Python {version} venv support is missing (ensurepip). On Debian/Ubuntu install python{version}-venv; on other systems install or enable the Python {version} venv/ensurepip support, then retry."}
    # Unlike command output, a venv diagnostic tail is useful. Apply the existing
    # privacy rules and additionally remove all absolute paths before reporting it.
    # Diagnostic paths are not shell tokens: spaces and quotes can be part of a
    # filename. Discard through the end of the line rather than risk a partial path.
    text = re.sub(r"(?:[A-Za-z]:[\\/]|(?<![\w\\])\\\\|(?<![\w/\\])/)[^\r\n]*", "[redacted]", text)
    for term in scanner.terms:
        text = re.sub(re.escape(term), "[redacted]", text, flags=re.I)
    for value in scanner.private_redactions:
        text = re.sub(re.escape(value), "[redacted]", text, flags=re.I)
    for name in scanner.private_names:
        text = name.sub("[redacted]", text)
    for pattern in [*scanner.patterns.values(), *SECRET_PATTERNS.values(), r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", r"(?<![\w:])[0-9A-Fa-f]*:[0-9A-Fa-f:]+(?:%[\w-]+)?(?![\w:])"]:
        text = re.sub(pattern, "[redacted]", text, flags=re.I)
    text = re.sub(r"[A-Za-z0-9_+=-]{32,}", lambda m: "[redacted]" if opaque_secret(m.group()) else m.group(), text)
    tail = "".join(c for c in text if c in "\n\t" or c.isprintable()).strip()[-1000:]
    return {"cause": "other-venv-error", "message": f"Python {version} virtual environment creation failed; the error does not identify missing ensurepip. See the redacted error tail.", "error_tail": tail}


def resolve_verify_tool(name: str, excluded: tuple[Path, ...]) -> Path:
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        if not Path(entry).is_absolute():
            continue
        candidate = Path(entry) / name
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        target = candidate.resolve(strict=True)
        if (not target.is_absolute() or not target.is_file() or not os.access(target, os.X_OK)
                or any(candidate.is_relative_to(path) or target.is_relative_to(path) for path in excluded)):
            raise OSError("verify-tool-missing")
        return target
    raise OSError("verify-tool-missing")


TEMP_FALLBACKS = ("/tmp", "/var/tmp")


def inside_repository(path: Path) -> bool:
    try:
        git(path, "rev-parse", "--git-dir")
    except AuditError:
        return False
    return True


def verify_parent() -> Path:
    for candidate in (tempfile.gettempdir(), *TEMP_FALLBACKS):
        path = Path(candidate).resolve()
        if path.is_dir() and os.access(path, os.W_OK | os.X_OK) and not inside_repository(path):
            return path
    raise AuditError("verify-workspace-in-repository", "no temporary folder outside a Git checkout; set TMPDIR to one")


def verify(repo: Path, report_dir: Path, scanner: Scanner, manifest: dict, timeout: int,
           *, tool_exclusions: tuple[Path, ...] = (), backend: str = "host", host_fallback: bool = False) -> dict:
    results = []
    result = {"status": "blocked", "commands": results, "dependencies": None}
    tools = verify_tools(manifest)
    if not manifest["quickstart"] or not manifest["checks"]:
        scanner.add("verification", "quality", "verification-not-configured", "release-check.json")
        return result
    for item in [*manifest["quickstart"], *manifest["checks"]]:
        if item.get("role", "quickstart") not in CHECK_ROLES:
            raise AuditError("command-role")
        argv = item.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
            raise AuditError("command-schema")
        if item in manifest["quickstart"]:
            doc = item.get("file", "README.md")
            if Path(doc).is_absolute() or ".." in Path(doc).parts:
                raise AuditError("quickstart-document-path")
            lines = (repo / doc).read_text().splitlines()
            number = item.get("line", 0)
            if not isinstance(number, int) or not 1 <= number <= len(lines) or shlex.split(lines[number - 1]) != argv:
                scanner.add("verification", "quality", "quickstart-document-mismatch", doc, number if isinstance(number, int) else 0)
                return result
    environment = None
    if backend == "coldbox":
        try:
            return verify_in_coldbox(repo, scanner, manifest, timeout, tools)
        except BackendUnavailable as error:
            if not host_fallback:
                explain(f"Coldbox did not run verification ({error}); nothing ran on this host. Pass --allow-host-fallback to run it here.")
                scanner.add("verification", "quality", "verify-backend-unavailable", "release-check.json", value=str(error),
                            details={"reason": str(error)})
                result["environment"] = {"backend": "coldbox", "unavailable": str(error)}
                return result
            explain(f"Coldbox did not run verification ({error}); running it on this host because --allow-host-fallback was given.")
            environment = {"backend": "host", "requested": "coldbox", "fallback": str(error)}
    if environment:
        result["environment"] = environment
    resolved_tools = {}
    excluded = tuple(path.resolve() for path in (repo, report_dir, *tool_exclusions))
    for name in tools:
        try:
            target = resolve_verify_tool(name, excluded)
        except (OSError, RuntimeError):
            scanner.add("verification", "quality", "verify-tool-missing", "release-check.json", value=name)
            return result
        resolved_tools[name] = target
    with tempfile.TemporaryDirectory(prefix="verify-", dir=verify_parent()) as tmp:
        workspace = Path(tmp)
        snapshot = workspace / "snapshot"
        copy_tree(repo, snapshot, manifest, scanner)
        clean = workspace / "clean"
        git(workspace, "clone", "-q", "--no-local", str(snapshot), str(clean))
        env_dir = workspace / "venv"
        creation_environment = safe_environment(workspace / "home", Path("/usr/bin"))
        code, output = command([sys.executable, "-m", "venv", str(env_dir)], workspace, creation_environment, timeout)
        if code:
            # Probe the same interpreter/environment; only a missing ensurepip module
            # identifies absent support. Import errors inside ensurepip are different.
            probe = "import sys\ntry:\n import ensurepip\nexcept ModuleNotFoundError as error:\n sys.exit(3 if error.name == 'ensurepip' else 4)"
            probe_code, _ = command([sys.executable, "-c", probe], workspace, creation_environment, timeout)
            scanner.add("verification", "quality", "venv-creation-failed", "release-check.json", value=output, details=venv_failure(output, scanner, ensurepip_missing=probe_code == 3))
            return result
        bin_dir = env_dir / "bin"
        for name, target in resolved_tools.items():
            try:
                if bin_dir.is_symlink() or not bin_dir.resolve().is_relative_to(env_dir.resolve()):
                    raise OSError("verify-tool-missing")
                (bin_dir / name).symlink_to(target)
            except OSError:
                scanner.add("verification", "quality", "verify-tool-missing", "release-check.json", value=name)
                return result
        environment = safe_environment(workspace / "home", bin_dir)
        for step, item in enumerate([*manifest["quickstart"], *manifest["checks"]], 1):
            role, budget = item.get("role", "quickstart"), item.get("timeout", timeout)
            code, output = command(item["argv"], clean, environment, budget)
            results.append({"step": step, "role": role, "exit_code": code, "output_fingerprint": fingerprint(output)})
            if code:
                details = {"role": role, "timeout": budget, "timeout_source": "manifest" if "timeout" in item else "cli"} if code == 124 else None
                scanner.add("verification", "quality", "command-timeout" if code == 124 else "command-failed",
                            item.get("file", "release-check.json"), item.get("line", 0), output, details=details)
                return result
        code, output = command([str(env_dir / "bin/python"), "-c", METADATA_SCRIPT], clean, environment, timeout)
        record_dependencies(result, code, output, clean, scanner, manifest)
    return result


def record_dependencies(result: dict, code: int, output: bytes, clean: Path, scanner: Scanner, manifest: dict) -> None:
    if code:
        scanner.add("verification", "license", "dependency-metadata-failed", "pyproject.toml", value=output)
    else:
        result["dependencies"] = dependency_audit(output, clean, scanner, manifest)
    # Verification must really install declared packages, not merely run help.
    if (clean / "pyproject.toml").exists():
        project = tomllib.loads((clean / "pyproject.toml").read_text()).get("project", {})
        # Invalid metadata has already added an unwaivable coverage finding.
        # Do not let this secondary presence check raise another exception.
        try:
            packages = json.loads(output) if not code else []
            installed = {p["name"].lower().replace("_", "-") for p in packages
                         if isinstance(p, dict) and isinstance(p.get("name"), str)} if isinstance(packages, list) else set()
        except (ValueError, RecursionError):
            installed = set()
        if project.get("name", "").lower().replace("_", "-") not in installed:
            scanner.add("verification", "quality", "project-not-installed", "pyproject.toml")
    result["status"] = "pass" if not code and result["dependencies"]["blocked"] == 0 else "blocked"


COLDBOX_INTERFACE = "cold.exec/v0"
COLDBOX_NO_ANSWER = 125
VM_CLEAN_ENV = ('env -i HOME="$root/home" TMPDIR="$root/home/tmp" PATH="$root/venv/bin:/usr/local/bin:/usr/bin:/bin" '
                'LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONNOUSERSITE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 '
                'XDG_CACHE_HOME="$root/home/cache" XDG_CONFIG_HOME="$root/home/config" '
                'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0')


class BackendUnavailable(Exception):
    pass


def coldbox_argv() -> list[str]:
    return shlex.split(env_value("COLDBOX") or "coldbox")


def coldbox_call(workspace: Path, timeout: int, *args: str) -> str:
    try:
        done = subprocess.run([*coldbox_argv(), *args], cwd=workspace, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise BackendUnavailable("coldbox-not-found") from None
    except (OSError, subprocess.TimeoutExpired):
        raise BackendUnavailable("coldbox-no-answer") from None
    if done.returncode:
        raise BackendUnavailable("coldbox-busy" if done.returncode == 75 else "coldbox-no-answer")
    return done.stdout.decode("utf-8", "replace")


def verify_in_coldbox(repo: Path, scanner: Scanner, manifest: dict, timeout: int, tools: list[str]) -> dict:
    results = []
    log = hashlib.sha256()
    result = {"status": "blocked", "commands": results, "dependencies": None}
    with tempfile.TemporaryDirectory(prefix="verify-", dir=verify_parent()) as tmp:
        workspace = Path(tmp)
        snapshot, clean = workspace / "snapshot", workspace / "clean"
        copy_tree(repo, snapshot, manifest, scanner)
        git(workspace, "clone", "-q", "--no-local", str(snapshot), str(clean))
        try:
            interface = json.loads(coldbox_call(workspace, timeout, "version")).get("interface")
        except (ValueError, AttributeError, RecursionError):
            interface = None
        if interface != COLDBOX_INTERFACE:
            raise BackendUnavailable("coldbox-interface")
        steps = [*manifest["quickstart"], *manifest["checks"]]
        ttl = sum(item.get("timeout", timeout) for item in steps) + 4 * timeout
        name = coldbox_call(workspace, timeout, "vm", "up", "--ttl", str(ttl)).strip()
        if not re.fullmatch(r"cbx-[A-Za-z0-9._-]+", name):
            raise BackendUnavailable("coldbox-no-answer")

        def run(args: list[str], budget: int, stdin: bytes | None = None) -> tuple[int, bytes]:
            code, output = command([*coldbox_argv(), "vm", "exec", name, "--", *args], workspace, dict(os.environ), budget,
                                   stdin=b"" if stdin is None else stdin, digest=log)
            if code == COLDBOX_NO_ANSWER:
                raise BackendUnavailable("coldbox-no-answer")
            return code, output

        def shell(script: str, budget: int) -> tuple[int, bytes]:
            return run(["sh", "-s"], budget, ('root="$PWD"; mkdir -p "$root/home/tmp"\n' + script).encode())

        try:
            code, release = run(["cat", "/etc/os-release"], timeout)
            lines = [line for line in release.decode("utf-8", "replace").splitlines() if line.startswith("PRETTY_NAME=")]
            try:
                image = "" if code else shlex.split(lines[0].removeprefix("PRETTY_NAME="))[0]
            except (IndexError, ValueError):
                image = ""
            if not image or len(image) > 200 or not image.isprintable():
                raise BackendUnavailable("coldbox-image-unknown")
            result["environment"] = {"backend": "coldbox", "interface": COLDBOX_INTERFACE, "image": image}
            archive = tempfile.SpooledTemporaryFile()
            with tarfile.open(fileobj=archive, mode="w") as bundle:
                bundle.add(clean, arcname="export")
            archive.seek(0)
            if run(["tar", "-xf", "-"], timeout, archive.read())[0]:
                raise BackendUnavailable("coldbox-transfer-failed")
            setup = f"set -e\n{VM_CLEAN_ENV} python3 -m venv venv\n" + "".join(
                f"tool=$(command -v {shlex.quote(tool)}) || exit {10 + index}\nln -s \"$tool\" venv/bin/{shlex.quote(tool)}\n"
                for index, tool in enumerate(tools))
            code, output = shell(setup, timeout)
            if 10 <= code < 10 + len(tools):
                scanner.add("verification", "quality", "verify-tool-missing", "release-check.json", value=tools[code - 10])
                return result
            if code:
                scanner.add("verification", "quality", "venv-creation-failed", "release-check.json", value=output,
                            details=venv_failure(output, scanner))
                return result
            for step, item in enumerate(steps, 1):
                role, budget = item.get("role", "quickstart"), item.get("timeout", timeout)
                code, output = shell(f"cd export && exec {VM_CLEAN_ENV} {shlex.join(item['argv'])} </dev/null\n", budget)
                results.append({"step": step, "role": role, "exit_code": code, "output_fingerprint": fingerprint(output)})
                if code:
                    details = {"role": role, "timeout": budget, "timeout_source": "manifest" if "timeout" in item else "cli"} if code == 124 else None
                    scanner.add("verification", "quality", "command-timeout" if code == 124 else "command-failed",
                                item.get("file", "release-check.json"), item.get("line", 0), output, details=details)
                    return result
            code, output = shell(f"cd export && exec {VM_CLEAN_ENV} python -c {shlex.quote(METADATA_SCRIPT)} </dev/null\n", timeout)
            record_dependencies(result, code, output, clean, scanner, manifest)
            return result
        finally:
            if "environment" in result:
                result["environment"]["log_sha256"] = log.hexdigest()
            try:
                coldbox_call(workspace, timeout, "vm", "down", name)
            except BackendUnavailable as error:
                explain(f"Coldbox did not delete its verification VM ({error}); its TTL removes it.")


RESIDUAL_RISK = ("A clean result is evidence of readiness, not a guarantee: the checks are pattern based, "
                 "so secrets or private data in forms they do not recognise, and every category not marked checked, can remain.")


def coverage_statement(repo: Path, source: Path, manifest: dict, scanner: Scanner, findings: list[dict],
                       verification: dict, allowlist: list[str] | None) -> dict:
    scanned = "incomplete" if any(f["category"] == "coverage" and not f["reviewed"] for f in findings) else "checked"
    categories = [
        ("secrets", scanned, "known token formats, assigned secrets, credential files and entropy in the tree, history and commit metadata"),
        ("personal data", scanned, "denylist terms, emails, phone numbers, home paths, internal hosts and private repository names"),
        ("licensing", "checked", "project licence and protected attribution files"),
        ("documentation and tests", "checked", "required documents, README limitations, issue templates and declared commands"),
        ("verification", "checked" if verification.get("status") == "pass" else "failed" if verification.get("commands") else "not run",
         "quickstart and declared checks in a clean clone"),
        ("dependencies", "checked" if verification.get("dependencies") is not None else "not run",
         "installed dependency licences, reported by verification"),
        ("deployment settings", scanned, "Terraform state and variables, kubeconfigs, registry auth files, Kubernetes Secrets, "
         "literal secrets in Actions, Dockerfile and compose settings; self-hosted runners listed for review"),
        ("media and binaries", "manual review", "listed for human review; contents other than expanded archives are not inspected"),
        ("application security", "not run", "no static or dynamic application security testing"),
        ("OCR", "not supported", "text inside images, including images in PDFs, is not read"),
        ("archives", scanned, "zip (docx/xlsx/pptx/jar), tar and gzip members and PDF Flate streams are expanded in memory and scanned; every archive is still listed for human review"),
        ("external scanners", "not run", "gitleaks, trufflehog, osv-scanner and bandit run only in the export workflow, after this report"),
        ("remote refs and unreachable objects", "not supported", "only local refs and reflogs are scanned"),
    ]
    excluded = {"default": [], "manifest": [], "allowlist": []}
    for rel in worktree_files(source)[0]:
        rel = rel.rstrip("/")
        if allowlist is not None and rel in allowlist:
            continue
        rule = ("default" if excluded_path(rel, DEFAULT_EXCLUDES) else "manifest" if excluded_path(rel, manifest["exclude"])
                else "allowlist" if allowlist is not None else None)
        if rule:
            excluded[rule].append(scanner.safe_path(rel))
    media = {(f["scope"], f["path"]) for f in findings if f["category"] == "media" and not f["reviewed"]}
    refs = git(repo, "for-each-ref", "--format=%(refname)").decode("utf-8", "surrogateescape").splitlines()
    return {"categories": [{"category": c, "status": s, "detail": d} for c, s, d in categories],
            "excluded_paths": excluded,
            "media_pending_review": [{"scope": s, "path": p} for s, p in sorted(media)],
            "history_refs": [*(scanner.safe_path(ref) for ref in refs), "HEAD", "reflogs"],
            "residual_risk": RESIDUAL_RISK}


def audit(repo: Path, terms: list[str], manifest: dict, private_repos: list[str], verify_commands: bool, report_dir: Path, timeout: int,
          *, tool_exclusions: tuple[Path, ...] = (), source: Path | None = None, allowlist: list[str] | None = None,
          verify_backend: str = "host", host_fallback: bool = False) -> dict:
    scanner = Scanner(terms, private_repos, manifest["approvals"])
    scanner.tree(repo)
    scanner.history(repo)
    licensing = license_audit(repo, scanner, manifest)
    quality_audit(repo, scanner, manifest)
    if verify_commands:
        verification = verify(repo, report_dir, scanner, manifest, timeout, tool_exclusions=tool_exclusions,
                              backend=verify_backend, host_fallback=host_fallback)
        if verification.get("dependencies") is not None:
            licensing["dependencies"] = "pass" if not verification["dependencies"]["blocked"] else "blocked"
    else:
        verification = {"status": "not-run", "commands": []}
        scanner.add("verification", "quality", "verification-not-run", "release-check.json")
    reviewable = [f for f in scanner.findings if f.get("reviewable")]
    findings = [f for f in scanner.findings if not f.get("reviewable")]
    unresolved = [f for f in findings if not f["reviewed"]]
    def safe_approval_value(key, value):
        if key == "path" and isinstance(value, str):
            return scanner.safe_path(value)
        if any(term.casefold() in str(value).casefold() for term in scanner.terms):
            return "[redacted]"
        return value
    stale_approvals = [
        {key: safe_approval_value(key, approval[key])
         for key in ("scope", "kind", "path", "fingerprint") if key in approval}
        for index, approval in enumerate(manifest["approvals"]) if index not in scanner.matched_approvals
    ]
    report = {"version": VERSION, "counts": dict(Counter(f["category"] for f in unresolved)), "reviewed_count": sum(f["reviewed"] for f in findings), "reviewable_count": len(reviewable), "reviewable_findings": reviewable, "stale_approvals": stale_approvals, "stats": dict(scanner.stats), "license": licensing, "verification": verification, "findings": findings,
              "coverage": coverage_statement(repo, source or repo, manifest, scanner, findings, verification, allowlist)}
    if scanner.fingerprint_upgrades:
        report["fingerprint_upgrades"] = scanner.fingerprint_upgrades
    report.update(outcome(report))
    return report


def fingerprint_upgrade_hint(reports: list[dict]) -> str | None:
    count = len({(u["path"], u["legacy_fingerprint"]) for report in reports for u in report.get("fingerprint_upgrades", [])})
    if not count:
        return None
    return (f"{count} source review(s) matched only a legacy fingerprint; replace each approval's fingerprint "
            "with the new one from fingerprint_upgrades in report.json (see README).")


def print_fail_findings(report: dict) -> None:
    if report.get("outcome") != "FAIL":
        return
    for finding in report.get("findings", []):
        if finding.get("reviewed", False):
            continue
        category, kind, path = (finding[key] for key in ("category", "kind", "path"))
        # Escape control characters so a filename cannot inject terminal output.
        path = json.dumps(path, ensure_ascii=True)[1:-1]
        if kind in {"npm-source-declarations-review", "bun-source-declarations-review", "dependency-license-review"}:
            label = {"npm-source-declarations-review": "npm source review",
                     "bun-source-declarations-review": "Bun source review",
                     "dependency-license-review": "dependency license review"}[kind]
            message = (f"{label} for {path} is not approved; add an approval with fingerprint "
                       f"{finding['fingerprint']} (see README)")
        elif kind == "command-timeout":
            source = '"timeout" in release-check.json' if finding["timeout_source"] == "manifest" else "--timeout"
            message = (f"{kind} in {path}; the {finding['role']} command exceeded its {finding['timeout']}s limit ({source}); "
                       "make it faster or raise that limit (see README)")
        else:
            action = {"personal": "remove or replace the private data, including affected history",
                      "secrets": "remove the secret from the tree and history; rotate any exposed credential",
                      "license": "resolve the license or attribution requirement",
                      "quality": "add or fix the required document, test or verification command",
                      "coverage": "resolve the scan coverage gap and rerun the audit",
                      "deployment-config": "remove the deployment file or replace the literal value with a secret reference; rotate any exposed credential",
                      "media": "review the media and remove it or add an exact approval"}.get(category, "resolve the finding and rerun the audit")
            message = f"{kind} in {path}; {action} (see README)"
            if kind == "denylist":
                stub = json.dumps({"scope": finding["scope"], "kind": kind, "path": finding["path"],
                                   "fingerprint": finding["fingerprint"], "reason": ""})
                message += ("; only if this text is meant to be public, such as the copyright holder's name, "
                            f"add {stub} to \"approvals\" in release-check.json and write in \"reason\" why it is public")
        print(f"{category}: {message}", file=sys.stderr)


def outcome(report: dict) -> dict:
    unresolved = [f for f in report.get("findings", []) if not f.get("reviewed", False)]
    reasons = {f["kind"] for f in unresolved}
    failed = any(f.get("category") != "coverage" and f["kind"] not in INCOMPLETE_KINDS for f in unresolved)
    if report.get("verification", {}).get("status") != "pass":
        reasons.add("verification-not-passed")
    licensing = report.get("license", {})
    if licensing.get("status") != "pass":
        reasons.add("license-not-passed")
    if licensing.get("dependencies") not in {"pass", "stdlib-only", "none (package.json)"}:
        reasons.add("dependencies-not-verified")
    for counter, reason in (("tree_files", "empty-tree"), ("history_commits", "empty-history")):
        count = report.get("stats", {}).get(counter)
        if type(count) is not int or count < 1:
            reasons.add(reason)
    status = "FAIL" if failed else "INCOMPLETE" if reasons else "PASS"
    return {"outcome": status, "reasons": sorted(reasons), "ready": status == "PASS"}


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def inventory_digest(repo: Path) -> str:
    entries = []
    def unreadable(error):
        raise error
    for root, dirs, files in os.walk(repo, followlinks=False, onerror=unreadable):
        directory = Path(root)
        entries.append((b"path", os.fsencode(directory.relative_to(repo)), b"directory",
                        str(stat.S_IMODE(directory.lstat().st_mode)).encode()))
        links = [name for name in dirs if (Path(root) / name).is_symlink()]
        dirs[:] = [name for name in dirs if name not in links]
        for name in files + links:
            path = Path(root) / name
            relative = path.relative_to(repo)
            if relative.parts[0] == ".git" and (relative == Path(".git/index") or name.endswith(".lock")):
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                kind, raw = b"symlink", os.fsencode(os.readlink(path))
            elif stat.S_ISREG(mode):
                kind, raw = b"file", path.read_bytes()
            else:
                raise AuditError("unsupported-inventory-file")
            entries.append((b"path", os.fsencode(relative), kind,
                            str(stat.S_IMODE(mode)).encode(), sha256(raw).encode()))
    entries.extend([(b"refs", git(repo, "for-each-ref")),
                    (b"head", git(repo, "rev-parse", "HEAD"), git(repo, "rev-parse", "--symbolic-full-name", "HEAD"))])
    digest = hashlib.sha256()
    for entry in sorted(entries):
        digest.update(len(entry).to_bytes(8, "big"))
        for field in entry:
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return digest.hexdigest()


GITHUB_REPOSITORY = re.compile(r"(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)"
                               r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?")
GITHUB_SECURITY_SETTINGS = ("secret_scanning", "secret_scanning_push_protection", "secret_scanning_non_provider_patterns",
                            "secret_scanning_validity_checks", "dependabot_security_updates")


def github_settings(target: str, resolved: str | None, timeout: int) -> dict | None:
    match = GITHUB_REPOSITORY.fullmatch(target)
    if match is None:
        return None
    unreadable = {"warnings": ["repository security settings are unreadable with gh api; check them on GitHub"]}
    if resolved != target:
        return unreadable
    try:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET", "repos/" + match[1]],
                                capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout)
        analysis = json.loads(result.stdout)["security_and_analysis"] if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, RecursionError):
        return unreadable
    if not isinstance(analysis, dict):
        return unreadable
    settings = {}
    for name in GITHUB_SECURITY_SETTINGS:
        entry = analysis.get(name)
        if name not in analysis:
            settings[name] = "absent"
        elif isinstance(entry, dict) and entry.get("status") in ("enabled", "disabled"):
            settings[name] = entry["status"]
        else:
            return unreadable
    return {"settings": settings, "warnings": [name + " is " + status for name, status in settings.items() if status != "enabled"]}


def is_github_managed_pull_ref(target: str, ref: str) -> bool:
    github = re.fullmatch(r"(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/)?", target)
    return github is not None and re.fullmatch(r"refs/pull/[1-9][0-9]*/(?:head|merge)", ref) is not None


def published_binding(repo: Path, target: str, ref: str, timeout: int, credentials: bool = False, expected=None) -> dict:
    if (not target or target.startswith("-") or "\0" in target or not ref.startswith("refs/heads/")
            or expected is not None and not all(re.fullmatch(r"[a-f0-9]{40,64}", value) for value in expected)):
        raise AuditError("published-target-invalid")
    try:
        git(repo, "check-ref-format", ref, timeout=timeout)
    except AuditError:
        raise AuditError("published-target-invalid") from None
    if Path(git(repo, "rev-parse", "--show-toplevel", timeout=timeout).decode().strip()).resolve() != repo:
        raise AuditError("published-target-not-root")
    grafts = Path(git(repo, "rev-parse", "--git-path", "info/grafts", timeout=timeout).decode().strip())
    if (repo / grafts).exists():
        raise AuditError("published-target-grafts")
    if git(repo, "for-each-ref", "--format=%(refname)", "refs/replace/", timeout=timeout):
        raise AuditError("published-target-replacements")
    if git(repo, "-c", "core.fsmonitor=false", "-c", "core.filemode=true", "status", "--porcelain=v1",
           "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none", timeout=timeout):
        raise AuditError("published-target-dirty")
    if any(entry.startswith(b"S ") or entry[:1].islower()
           for entry in git(repo, "ls-files", "-v", "-z", timeout=timeout).split(b"\0")):
        raise AuditError("published-target-dirty")
    try:
        rows = git(repo, "ls-remote", "--refs", target, ref, timeout=timeout, credentials=credentials).decode().splitlines()
    except (AuditError, OSError, ValueError, subprocess.SubprocessError):
        raise AuditError("published-ref-unavailable") from None
    if not rows:
        raise AuditError("published-ref-missing")
    if len(rows) != 1 or rows[0].split("\t")[1:] != [ref]:
        raise AuditError("published-ref-invalid")
    head = rows[0].split("\t")[0]
    if not re.fullmatch(r"[a-f0-9]{40,64}", head):
        raise AuditError("published-ref-invalid")
    try:
        local_head = git(repo, "rev-parse", "HEAD", timeout=timeout).decode().strip()
    except AuditError:
        raise AuditError("published-clone-empty", "the clone has no checked-out commit; clone the published branch with "
                         "git clone --branch <branch>") from None
    if local_head != head:
        raise AuditError("published-target-stale")
    try:
        rows = [row.split("\t") for row in git(repo, "ls-remote", target, timeout=timeout, credentials=credentials).decode().splitlines()]
    except (AuditError, OSError, ValueError, subprocess.SubprocessError):
        raise AuditError("published-ref-unavailable") from None
    resolved_target = git(repo, "ls-remote", "--get-url", target, timeout=timeout, credentials=credentials).decode().strip()
    published_history = set(git(repo, "rev-list", "HEAD", timeout=timeout).decode().split())
    tags = sorted(row[-1] for row in rows if row[-1].startswith("refs/tags/") and row[0] in published_history)
    if {row[-1] for row in rows if not (is_github_managed_pull_ref(target, row[-1]) and is_github_managed_pull_ref(resolved_target, row[-1]))} - {"HEAD", *tags} != {ref} or any(row[-1] == "HEAD" and row[0] != head for row in rows):
        raise AuditError("published-extra-refs")
    tree = git(repo, "rev-parse", "HEAD^{tree}", timeout=timeout).decode().strip()
    if expected is not None and [head, tree] != list(expected):
        raise AuditError("published-receipt-mismatch", "the target holds a commit or tree other than the signed export; do not make it public")
    return {"head": head, "tree": tree, "inventory": inventory_digest(repo), "tags": tags}


def receipt_bindings(repo: Path, args, *, tolerate_errors: bool = False) -> dict:
    sources = {
        "inventory": lambda: inventory_digest(repo),
        "recipe": lambda: sha256(canonical_json(manifest_for(repo, args.manifest))),
        "policy": lambda: sha256(canonical_json({
            "denylist_sha256": sha256(Path(args.denylist).expanduser().read_bytes()),
            "private_repos_sha256": sha256(canonical_json(sorted(args.private_repo))),
            "default_excludes": DEFAULT_EXCLUDES, "verify": args.verify, "timeout": args.timeout})),
        "scanners": lambda: sha256(canonical_json({
            "release-check": {"version": VERSION, "sha256": sha256(Path(__file__).read_bytes())},
            "python": sys.version, "git": git(repo, "--version").decode().strip()})),
    }
    bindings = {}
    for name, read in sources.items():
        try:
            bindings[name] = read()
        except (AuditError, OSError, ValueError, TypeError, RecursionError):
            if not tolerate_errors:
                raise
            bindings[name] = None
    return bindings


def write_receipt(directory: Path, repo: Path, report: dict, args, *, inventory: str, source: dict | None = None):
    receipt = {"schema_version": 1, "outcome": report["outcome"], "reasons": report["reasons"],
               "created_at": datetime.now(timezone.utc).isoformat(),
               "export_head": git(repo, "rev-parse", "HEAD").decode().strip(),
               "export_tree": git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
               **(source or {}),
               **({"verification_environment": report["verification"]["environment"]}
                  if "environment" in report.get("verification", {}) else {}),
               "bindings": {**receipt_bindings(repo, args), "inventory": inventory}}
    receipt["receipt_sha256"] = sha256(canonical_json(receipt))
    fd = os.open(directory / "receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(canonical_json(receipt) + b"\n")


STALE_RECEIPT_HINTS = {
    "policy": "policy changed: pass the same --denylist, --private-repo, --verify and --timeout used for the export",
    "recipe": "recipe changed: pass the same --manifest (or restore release-check.json) used for the export",
    "scanners": "scanners changed: the engine, Python or Git version changed since the export; re-export with this engine",
    "inventory": "inventory changed: the export folder changed after the receipt was written; re-export",
}

RECEIPT_FIELDS = {"schema_version", "outcome", "reasons", "created_at", "export_head", "export_tree", "bindings", "receipt_sha256"}


def valid_verification_environment(environment) -> bool:
    def slug(value):
        return isinstance(value, str) and bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value))
    if not isinstance(environment, dict) or not all(isinstance(key, str) for key in environment):
        return False
    if set(environment) == {"backend", "interface", "image", "log_sha256"}:
        image = environment["image"]
        return (environment["backend"] == "coldbox" and environment["interface"] == COLDBOX_INTERFACE
                and isinstance(image, str) and 0 < len(image) <= 200 and image.isprintable()
                and isinstance(environment["log_sha256"], str) and bool(re.fullmatch(r"[a-f0-9]{64}", environment["log_sha256"])))
    if set(environment) == {"backend", "unavailable"}:
        return environment["backend"] == "coldbox" and slug(environment["unavailable"])
    if set(environment) == {"backend", "requested", "fallback"}:
        return environment["backend"] == "host" and environment["requested"] == "coldbox" and slug(environment["fallback"])
    return False


def validate_receipt(path: Path, repo: Path, args) -> dict:
    invalid = {"outcome": "INCOMPLETE", "reasons": ["receipt-invalid"], "mismatched": []}

    def reject(reason: str) -> dict:
        explain(reason)
        return invalid

    try:
        with path.open("rb") as handle:
            if os.fstat(handle.fileno()).st_size > MAX_RECEIPT_BYTES:
                return reject("receipt file is too large")
            raw = handle.read(MAX_RECEIPT_BYTES + 1)
    except OSError:
        return reject("receipt file does not exist or cannot be read")
    if len(raw) > MAX_RECEIPT_BYTES:
        return reject("receipt file is too large")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_json_object)
    except ValueError:
        return reject("receipt file is not valid JSON")
    except (RecursionError, MemoryError):
        return reject("receipt file is too large or too deeply nested")
    if not isinstance(receipt, dict):
        return reject("receipt must be a JSON object")
    missing = sorted(RECEIPT_FIELDS - receipt.keys())
    if missing:
        return reject("receipt is missing required fields: " + ", ".join(missing))
    try:
        body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if (type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1
                or receipt.get("receipt_sha256") != sha256(canonical_json(body))
                or receipt.get("outcome") not in {"PASS", "FAIL", "INCOMPLETE"}
                or not isinstance(receipt.get("reasons"), list)
                or any(not isinstance(r, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", r) for r in receipt["reasons"])
                or not isinstance(receipt.get("bindings"), dict)
                or set(receipt["bindings"]) != {"inventory", "recipe", "policy", "scanners"}
                or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{64}", v) for v in receipt["bindings"].values())
                or not isinstance(receipt.get("created_at"), str)
                or any(not isinstance(receipt.get(k), str) or not re.fullmatch(r"[a-f0-9]{40,64}", receipt[k]) for k in ("export_head", "export_tree"))
                or any(not isinstance(receipt[k], str) or not re.fullmatch(r"[a-f0-9]{40,64}", receipt[k]) for k in set(receipt) & {"source_head", "source_tree"})
                or ("verification_environment" in receipt and not valid_verification_environment(receipt["verification_environment"]))
                or (receipt["outcome"] == "PASS" and receipt["reasons"])):
            return reject("receipt fields are malformed or do not match its checksum")
        if not repo.is_dir():
            explain("export folder does not exist or is not a folder")
        current = receipt_bindings(repo, args, tolerate_errors=True)
        mismatched = sorted(key for key in current if current[key] != receipt["bindings"][key])
        if "inventory" not in mismatched and (
                receipt["export_head"] != git(repo, "rev-parse", "HEAD").decode().strip()
                or receipt["export_tree"] != git(repo, "rev-parse", "HEAD^{tree}").decode().strip()):
            mismatched = sorted(set(mismatched) | {"inventory"})
        for key in mismatched if repo.is_dir() else ():
            explain(STALE_RECEIPT_HINTS[key])
        return {"outcome": "INCOMPLETE" if mismatched else receipt["outcome"],
                "reasons": ["receipt-stale"] if mismatched else receipt["reasons"], "mismatched": mismatched}
    except (AuditError, OSError, ValueError, TypeError, KeyError, RecursionError, MemoryError):
        return reject("receipt could not be checked against the export folder")


def scrub_plan(report: dict, repo: Path, manifest: dict, scanner: Scanner) -> dict:
    drop = [scanner.safe_path(rel) for rel in worktree_files(repo)[0]
            if excluded_path(rel, [*DEFAULT_EXCLUDES, *manifest["exclude"]])]
    replace = [f for f in report["findings"] if f["scope"] == "tree" and f["category"] in {"personal", "secrets"} and not f["reviewed"]]
    return {"drop_files": sorted(drop), "replace_or_remove": replace, "flatten_history": True, "review_media": [f for f in report["findings"] if f["category"] == "media" and not f["reviewed"]], "preserve_attribution": True}


def coverage_markdown(coverage: dict) -> list[str]:
    def cell(text: str) -> str:
        return text.replace("|", "&#124;").replace("<", "&lt;").replace(">", "&gt;")
    def listing(items: list[str]) -> str:
        return ", ".join(map(cell, items)) or "none"
    excluded = coverage["excluded_paths"]
    md = ["", "## Coverage", "", "| Category | Status | Detail |", "| --- | --- | --- |"]
    md += [f"| {c['category']} | {c['status']} | {c['detail']} |" for c in coverage["categories"]]
    md += ["", "Excluded by default rules: " + listing(excluded["default"]),
           "", "Excluded by release-check.json: " + listing(excluded["manifest"]),
           "", "Excluded by the export allowlist: " + listing(excluded["allowlist"]),
           "", "Media pending review: " + listing([m["scope"] + " " + m["path"] for m in coverage["media_pending_review"]]),
           "", "History refs scanned: " + listing(coverage["history_refs"]),
           "", "Residual risk: " + coverage["residual_risk"]]
    return md


def write_reports(directory: Path, report: dict):
    content = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    md = ["# Release audit", "", "Ready: " + str(report["ready"]).lower(), "", "| Category | Unresolved |", "| --- | ---: |"]
    md += [f"| {k} | {v} |" for k, v in report["counts"].items()]
    md += ["", "License: " + json.dumps(report["license"], sort_keys=True), "", "Verification: " + json.dumps(report["verification"], sort_keys=True), "", "## Blocking and approved findings", "", "| Scope | Kind | Path | Line | Fingerprint | Term index | Status | Reason |", "| --- | --- | --- | ---: | --- | ---: | --- | --- |"]
    diagnostics = []
    for f in report["findings"]:
        path = f["path"].replace("|", "&#124;").replace("<", "&lt;").replace(">", "&gt;")
        if "message" in f:
            diagnostics.append(f["message"] + (" Error tail: " + json.dumps(f["error_tail"]) if "error_tail" in f else ""))
        status = f.get("review_status", "reviewed" if f["reviewed"] else "blocking")
        reason = f.get("reason", "").replace("|", "&#124;").replace("<", "&lt;").replace(">", "&gt;")
        md.append(f"| {f['scope']} | {f['kind']} | {path} | {f['line']} | {f['fingerprint']} | {f.get('term_index', '')} | {status} | {reason} |")
    if report.get("stale_approvals"):
        md += ["", "## Stale approvals", "", "These approvals matched no finding and should be removed or updated.", "", "| Scope | Kind | Path | Fingerprint |", "| --- | --- | --- | --- |"]
        md += [f"| {a.get('scope', '')} | {a.get('kind', '')} | {a.get('path', '')} | {a.get('fingerprint', '')} |" for a in report["stale_approvals"]]
    if diagnostics:
        md += ["", *diagnostics]
    md += ["", "## Reviewable private-term hits (nonblocking)", "", "Count: " + str(report.get("reviewable_count", 0)), "", "| Scope | Path | Line | Fingerprint | Term index |", "| --- | --- | ---: | --- | ---: |"]
    for f in report.get("reviewable_findings", []):
        path = f["path"].replace("|", "&#124;").replace("<", "&lt;").replace(">", "&gt;")
        md.append(f"| {f['scope']} | {path} | {f['line']} | {f['fingerprint']} | {f['term_index']} |")
    if "coverage" in report:
        md += coverage_markdown(report["coverage"])
    if "export" in report:
        md += ["", "## Export", "", "Ready: " + str(report["export"]["ready"]).lower(), "", "Counts: " + json.dumps(report["export"]["counts"], sort_keys=True), "", "Export findings and verification are in report.json."]
    if "scrub_plan" in report:
        md += ["", "## Scrub plan", "", "```json", json.dumps(report["scrub_plan"], indent=2), "```"]
    for name, text in (("report.json", content), ("report.md", "\n".join(md) + "\n")):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    legacy_repo = bool(argv and Path(argv[0]).is_dir() and (len(argv) == 1 or argv[1].startswith("-")))
    if argv and not legacy_repo and argv[0] in {"preflight", "plan", "check", "export", "approve", "publish", "ship", "status", "confirm-public", "prune", "review", "sanitize", "release", "survey"}:
        from release_workflow import main as workflow_main
        return workflow_main(argv)
    parser = PrivateParser(description=__doc__, epilog="Workflow commands: preflight, plan, check, export, approve, publish, ship, status, confirm-public, prune, review, sanitize, release, survey. Use COMMAND --help.")
    parser.add_argument("repo", type=Path, nargs="?")
    parser.add_argument("--version", action="version", version=f"coldrelease {VERSION}")
    parser.add_argument("--requirements", action="store_true", help="Print required files, README headings and manifest shape without scanning")
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--private-repo", action="append", default=[], help="Known-private repo URL on any host, or owner/name; kept out of reports")
    parser.add_argument("--verify", action="store_true", help="Execute reviewed manifest quickstart/check argv in a fresh local clone and venv")
    parser.add_argument("--verify-backend", choices=VERIFY_BACKENDS, default="host",
                        help="With --verify: run the commands on this host (default) or in a disposable Coldbox VM (cold.exec/v0)")
    parser.add_argument("--allow-host-fallback", action="store_true",
                        help="With --verify-backend coldbox: run on this host when Coldbox does not answer, instead of INCOMPLETE")
    parser.add_argument("--published-target", nargs=2, metavar=("URL", "BRANCH_REF"),
                        help="Final gates: require --verify and a clean repo at the current published ref; recheck after scanning")
    parser.add_argument("--use-git-credentials", action="store_true",
                        help="Let --published-target ask the credential helpers in your global git config; nothing else from it is used")
    parser.add_argument("--expected-export", nargs=2, metavar=("EXPORT_HEAD", "EXPORT_TREE"),
                        help="With --published-target: FAIL unless the target holds exactly this signed export commit and tree")
    parser.add_argument("--timeout", type=positive_seconds, default=300)
    parser.add_argument("--scrub-plan", action="store_true")
    parser.add_argument("--export", type=Path)
    parser.add_argument("--validate-receipt", type=Path, nargs=2, metavar=("RECEIPT_JSON", "EXPORT_DIR"))
    args = parser.parse_args(argv)
    if args.requirements:
        print(requirements_text(), end="")
        return 0
    if args.repo is None and not args.validate_receipt:
        parser.error("pass a repository or --requirements")
    args.denylist = args.denylist or env_value("DENYLIST")
    if not args.denylist:
        if args.repo is not None and not os.path.isdir(os.path.expanduser(args.repo)):
            parser.error("repository path does not exist or is not a directory")
        parser.error("pass --denylist or set COLDRELEASE_DENYLIST")
    if args.published_target and (not args.verify or args.export or args.validate_receipt):
        parser.error("--published-target requires --verify and cannot export or validate an old receipt")
    if args.use_git_credentials and not args.published_target:
        parser.error("--use-git-credentials requires --published-target")
    if args.verify_backend != "host" and not args.verify:
        parser.error("--verify-backend requires --verify")
    if args.allow_host_fallback and args.verify_backend == "host":
        parser.error("--allow-host-fallback requires --verify-backend coldbox")
    if args.expected_export and not args.published_target:
        parser.error("--expected-export requires --published-target")
    if args.validate_receipt:
        result = validate_receipt(args.validate_receipt[0].expanduser(), args.validate_receipt[1].expanduser().resolve(), args)
        print(json.dumps(result, sort_keys=True))
        return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[result["outcome"]]
    os.umask(0o077)
    directory = None
    reports_reason = "reports folder cannot be created or written; pass --reports a writable folder"
    try:
        repo = args.repo.expanduser().resolve()
        denylist = Path(args.denylist).expanduser().resolve()
        if denylist == repo or repo in denylist.parents:
            raise AuditError("denylist-inside-source")
        try:
            terms = load_terms(denylist)
        except OSError:
            print("denylist file does not exist or cannot be read", file=sys.stderr)
            raise
        manifest = manifest_for(repo, args.manifest)
        scanner = Scanner(terms, args.private_repo, manifest["approvals"])
        root = Path(args.reports or env_value("REPORTS") or "~/.local/state/coldrelease").expanduser().resolve()
        if root == repo or repo in root.parents:
            raise AuditError("reports-inside-source")
        if args.export:
            target = args.export.expanduser().resolve()
            if root == target or target in root.parents:
                raise AuditError("reports-inside-export")
            if target == denylist or target in denylist.parents:
                raise AuditError("export-contains-denylist")
        if args.use_git_credentials:
            global_credential_helpers()
        published = published_binding(repo, *args.published_target, args.timeout, args.use_git_credentials, args.expected_export) if args.published_target else None
        if published is not None and any(scanner.safe_path(tag) != tag for tag in published["tags"]):
            raise AuditError("published-extra-refs")
        # Raw repository names never become report directory names if they contain a term.
        if Path(os.fsdecode(git_repository(repo, "rev-parse", "--show-toplevel").removesuffix(b"\n"))).resolve() != repo:
            explain("repository path is inside another Git repository; pass its top-level folder")
            raise AuditError("not-repository-root")
        common_dir = Path(git_repository(repo, "rev-parse", "--git-common-dir").decode().strip())
        if not common_dir.is_absolute():
            common_dir = repo / common_dir
        repo_name = common_dir.resolve().parent.name if common_dir.name == ".git" else repo.name
        name = scanner.safe_path(repo_name)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        directory = root / name / stamp
        try:
            directory.mkdir(mode=0o700, parents=True)
            directory.chmod(0o700)
        except OSError:
            directory = None
            raise AuditError("reports-unwritable", reports_reason) from None
        tool_exclusions = (repo, root, args.export.expanduser().resolve()) if args.export else (repo, root)
        backend = {"verify_backend": args.verify_backend, "host_fallback": args.allow_host_fallback}
        report = audit(repo, terms, manifest, args.private_repo, args.verify, directory, args.timeout, tool_exclusions=tool_exclusions, **backend)
        if args.scrub_plan:
            report["scrub_plan"] = scrub_plan(report, repo, manifest, scanner)
        if args.export:
            target = args.export.expanduser().resolve()
            copy_tree(repo, target, manifest, scanner)
            candidate_inventory = inventory_digest(target)
            terms = export_terms(terms, repo)
            export_report = audit(target, terms, manifest_for(target, args.manifest), args.private_repo, args.verify, directory, args.timeout, tool_exclusions=tool_exclusions, source=repo, **backend)
            for finding in scanner.findings:
                export_report["findings"].append(finding)
                export_report["counts"][finding["category"]] = export_report["counts"].get(finding["category"], 0) + 1
            preserve_historical_attribution(repo, target, export_report, terms)
            audited_inventory = inventory_digest(target)
            if audited_inventory != candidate_inventory:
                finding_scanner = Scanner(terms)
                finding_scanner.add("export", "quality", "candidate-mutated", ".")
                export_report["findings"].extend(finding_scanner.findings)
                export_report["counts"]["quality"] = export_report["counts"].get("quality", 0) + 1
            export_report.update(outcome(export_report))
            export_report["coverage"]["excluded_paths"] = report["coverage"]["excluded_paths"]
            report["export"] = export_report
        if published is not None:
            if published_binding(repo, *args.published_target, args.timeout, args.use_git_credentials, args.expected_export) != published:
                raise AuditError("published-target-mutated")
            report["published_target"] = published
            url = args.published_target[0]
            try:
                resolved = git(repo, "ls-remote", "--get-url", url, timeout=args.timeout,
                               credentials=args.use_git_credentials).decode().strip()
            except (AuditError, OSError, subprocess.SubprocessError):
                resolved = None
            settings = github_settings(url, resolved, args.timeout)
            if settings is not None:
                report["github_settings"] = settings
        try:
            write_reports(directory, report)
        except OSError:
            directory = None
            raise AuditError("reports-unwritable", reports_reason) from None
        if "export" in report:
            write_receipt(directory, target, report["export"], args, inventory=audited_inventory)
        summary = {"outcome": report["outcome"], "ready": report["ready"], "counts": report["counts"]}
        if published is not None:
            summary["published_target"] = published
            if "github_settings" in report:
                summary["github_settings"] = report["github_settings"]
        if "export" in report:
            summary["export_outcome"] = report["export"]["outcome"]
            summary["export_ready"] = report["export"]["ready"]
            summary["export_counts"] = report["export"]["counts"]
        summary["report"] = name + "/" + stamp + "/report.json"
        print(json.dumps(summary))
        if args.reports is None:
            location = str(directory / "report.json")
            home = str(Path.home())
            beyond_home = "~" + location[len(home):] if location.startswith(home + os.sep) else location
            if (scanner.safe_path(beyond_home) != beyond_home
                    or any(term.casefold() in location.casefold() for term in scanner.terms)):
                location = "[path-" + fingerprint(location) + "]"
            print("report: " + location, file=sys.stderr)
        print_fail_findings(report)
        if "export" in report:
            print_fail_findings(report["export"])
        hint = fingerprint_upgrade_hint([report, report.get("export", {})])
        if hint:
            print(hint, file=sys.stderr)
        if args.scrub_plan:
            print(json.dumps(report["scrub_plan"], indent=2))
        return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[report.get("export", report)["outcome"]]
    except (AuditError, OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as exc:
        if directory is not None and not (directory / "report.json").exists():
            incomplete = {"version": VERSION, "ready": False, "counts": {"coverage": 1}, "license": {"status": "unknown"}, "verification": {"status": "incomplete"}, "findings": [{"scope": "audit", "category": "coverage", "kind": "audit-incomplete", "path": "@audit", "line": 0, "fingerprint": fingerprint(b"audit-incomplete"), "reviewed": False}]}
            incomplete["coverage"] = {"categories": [{"category": "audit", "status": "not run", "detail": "the audit stopped before it finished; no category was fully checked"}],
                                      "excluded_paths": {"default": [], "manifest": [], "allowlist": []},
                                      "media_pending_review": [], "history_refs": [], "residual_risk": RESIDUAL_RISK}
            incomplete.update(outcome(incomplete))
            try:
                write_reports(directory, incomplete)
            except OSError:
                exc = AuditError("reports-unwritable", reports_reason)
        error = str(exc) if isinstance(exc, AuditError) else "audit-incomplete"
        failed = error in {"published-extra-refs", "published-receipt-mismatch"}
        failure = {"outcome": "FAIL" if failed else "INCOMPLETE", "ready": False, "error": error}
        detail = exc.detail if isinstance(exc, AuditError) else failure_cause(exc)
        if detail:
            failure["detail"] = detail
        if error == "reports-unwritable":
            print(exc.detail, file=sys.stderr)
            print(json.dumps(failure, separators=(",", ":")))
        else:
            print(json.dumps(failure, separators=(",", ":")), file=sys.stderr)
        return 1 if failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
