"""Local, human-approved release workflow over the Coldrelease audit engine."""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager, redirect_stderr, redirect_stdout, suppress
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import io
import json
import locale
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

import release_check as rc
from release_templates import TEMPLATES

COMMANDS = ("preflight", "plan", "check", "export", "approve", "publish", "ship", "status", "confirm-public", "prune", "review", "sanitize", "release", "survey")
SCANNERS = ("gitleaks", "trufflehog", "osv-scanner", "bandit")
SECRET_SCANNERS = ("gitleaks", "trufflehog")
OSV_BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}
MINIMUM_VERSIONS = {"osv-scanner": (r"osv-scanner version: (\d+)\.(\d+)\.(\d+)", (2, 5, 1)),
                    "bandit": (r"bandit (\d+)\.(\d+)\.(\d+)", (1, 8, 0))}
BANDIT_LEVELS = {"UNDEFINED", "LOW", "MEDIUM", "HIGH"}
NOTICE = "PASS means the declared checks passed; it does not guarantee safety."
GUARD_REMOTE = re.compile(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
RECORD_MAX_AGE_DAYS = 7
APPROVAL_KEYS = {"schema_version", "receipt_sha256", "source_head", "source_tree", "scanners", "target", "ref",
                 "expected_public_head", "release_head", "denylist", "recipe", "allowlist", "allowlist_diff", "changes_sha256",
                 "target_visibility"}
RECIPE_KEYS = ("quickstart", "checks", "verify_tools")
RUN_ID = r"[A-Za-z0-9][A-Za-z0-9._-]*"
REVIEW_DECISIONS = ("approve", "exclude", "fix")
TRANSFORM_KEYS = {"drop": {"op", "path"}, "replace": {"op", "path", "fingerprint", "placeholder"}, "env-example": {"op"},
                  "strip-metadata": {"op", "path"}, "add": {"op", "template"}}
ATTRIBUTION_FILE = re.compile(r"(?:^|/)(?:AUTHORS|CONTRIBUTORS|ATTRIBUTION|COPYRIGHT|CREDITS)[^/]*$", re.I)
RECIPE_FINDINGS = {"quickstart-not-declared", "test-command-not-declared"}
REVIEW_CHOICES = {"a": "approve", "e": "exclude", "f": "fix", "s": "skip", "": "skip"}
PYTHON_INSTALLS = [["python", "-m", "pip", "install"], ["python3", "-m", "pip", "install"], ["pip", "install"], ["pip3", "install"]]
NPM_INSTALLS = [["npm", "install"], ["npm", "ci"]]
NPM_SCRIPTS = {"test": ("tests", ["npm", "test"]), "lint": ("lint", ["npm", "run", "lint"]),
               "typecheck": ("types", ["npm", "run", "typecheck"]), "build": ("build", ["npm", "run", "build"])}


def read_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=rc.unique_json_object)


def write_json(path, value):
    write_bytes(path, rc.canonical_json(value) + b"\n")


def write_bytes(path, data):
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path)
    finally:
        with suppress(OSError):
            os.unlink(temp)


def require(condition, reason):
    if not condition:
        raise rc.AuditError(reason)


@contextmanager
def run_lock(run):
    lock = run / ".lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = os.stat(lock, follow_symlinks=False).st_ino == os.fstat(fd).st_ino
        except (BlockingIOError, FileNotFoundError):
            held = False
        require(held, "run-locked")
        try:
            yield
        finally:
            lock.unlink()
    finally:
        os.close(fd)


def runs_root():
    base = os.environ.get("XDG_STATE_HOME", "")
    base = Path(base) if os.path.isabs(base) else Path.home() / ".local" / "state"
    return base.resolve() / "coldrelease" / "runs"


def state_key(name, identity):
    return (re.sub(r"[^A-Za-z0-9._-]", "-", name).lstrip(".-")[:64] or "source") + "-" + rc.sha256(identity)[:12]


def state_root(repo):
    if repo.name == "source" and repo.parent.parent.parent == runs_root() and (repo.parent / "source.json").is_file():
        return repo.parent.parent
    root = runs_root() / state_key(repo.name, os.fsencode(repo))
    require(not root.is_relative_to(repo), "run-state-inside-source")
    return root


def remote_url(text):
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        require(not re.search(r"[\x00-\x20\x7f]", text) and parsed.scheme in {"https", "ssh", "file"}
                and (parsed.netloc or parsed.scheme == "file"), "source-url-invalid")
        require(parsed.password is None and (parsed.scheme != "https" or not ("@" in parsed.netloc or parsed.query or parsed.fragment)),
                "source-url-credentials")
        return text
    try:
        if Path(text).expanduser().exists():
            return None
    except OSError as error:
        if error.errno != errno.ENAMETOOLONG:
            raise
    if re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~-][A-Za-z0-9._~/-]*", text):
        return text
    if re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}(?:\.git)?", text):
        return "https://github.com/" + text.removesuffix(".git") + ".git"
    return None


def repository_key(url):
    if "://" in url:
        parsed = urllib.parse.urlsplit(url)
        url = (parsed.hostname or "") + parsed.path
    else:
        url = re.sub(r"^([^/@:]+@)?([^/:]+):(?!/)", r"\2/", url)
    return url.rstrip("/").removesuffix(".git").lower()


def source_repository(url, run_id):
    require(bool(re.fullmatch(RUN_ID, run_id)), "run-invalid")
    name = re.split(r"[/:]", url.rstrip("/"))[-1].removesuffix(".git")
    return runs_root() / state_key(name, url.encode()) / run_id / "source"


def clone_source(url, checkout, timeout, credentials):
    workspace = checkout.parent
    require(not any(p.is_symlink() for p in (workspace, *workspace.parents)), "run-symlink")
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    with run_lock(workspace):
        if (workspace / "source.json").is_file():
            return
        for partial in (workspace / "mirror.git", checkout):
            shutil.rmtree(partial, ignore_errors=True)
        try:
            rc.git(workspace, "clone", "--quiet", "--mirror", "--", url, "mirror.git", timeout=timeout, credentials=credentials)
            rc.git(workspace, "clone", "--quiet", "--", "mirror.git", checkout.name, timeout=timeout)
        except (rc.AuditError, subprocess.SubprocessError):
            raise rc.AuditError("source-clone-failed") from None
        rows = rc.git(workspace / "mirror.git", "for-each-ref", "--format=%(refname) %(objectname)").decode().splitlines()
        write_json(workspace / "source.json", {"schema_version": 1, "url": url, "refs": dict(row.split(" ", 1) for row in rows)})


def resolve_source(args):
    url = remote_url(args.repo)
    if url is None:
        require(not args.use_git_credentials or args.command != "preflight", "git-credentials-selection")
        return Path(args.repo), None
    require(args.command == "preflight" or args.run, "run-required")
    args.run = args.run or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    checkout = source_repository(url, args.run)
    if args.command == "preflight":
        clone_source(url, checkout, args.timeout, args.use_git_credentials)
    require((checkout.parent / "source.json").is_file(), "source-not-cloned")
    return checkout, url


def legacy_root(repo):
    return repo / ".coldrelease" / "runs"


def run_directory(repo, run_id):
    require(bool(re.fullmatch(RUN_ID, run_id)), "run-invalid")
    legacy = legacy_root(repo) / run_id
    run = legacy if legacy.is_dir() else state_root(repo) / run_id
    require(not any(p.is_symlink() for p in (run, *run.parents)), "run-symlink")
    return run


def other_runs(repo, run):
    return [p for root in (state_root(repo), legacy_root(repo)) if root.is_dir() and not root.is_symlink()
            for p in root.iterdir() if p != run and p.is_dir() and not p.is_symlink()]


def forbidden(rel):
    path = Path(rel)
    return (any(p.casefold() in {".git", ".coldrelease", ".worktrees", "worktrees", ".agents", ".claude", ".codex", ".cursor",
                                "scratch", ".scratch", "evidence", "audit", "receipts"} for p in path.parts)
            or any(re.match(r"(?i)^(?:AGENTS|CLAUDE|STATE|VISION)(?:[._-]|$)", p)
                   and Path(p).suffix.casefold() in {"", ".md", ".txt", ".json", ".yaml", ".yml"} for p in path.parts)
            or bool(re.search(r"(?i)(?:^|/)(?:public-export|maintainer|private)(?:[./-]|$)", rel))
            or rc.match_path(rel, rc.DEFAULT_EXCLUDES))


def export_path_reviewed(repo, rel, manifest):
    if (any(part.casefold() in {".git", ".coldrelease"} for part in Path(rel).parts)
            or any(char in rel for char in "*?[]\\") or rc.match_path(rel, rc.DEFAULT_EXCLUDES)):
        return False
    reviews = [item for item in manifest["approvals"]
               if item.get("scope") == "tree" and item.get("kind") == "export-path-review"
               and item.get("path") == rel and isinstance(item.get("reason"), str)
               and item["reason"].strip()]
    if not reviews:
        return False
    digest = rc.sha256((repo / rel).read_bytes())
    return any(item.get("source_sha256") == digest for item in reviews)


def validate_paths(repo, paths, manifest):
    tracked = {os.fsdecode(p) for p in rc.git(repo, "ls-files", "-z").split(b"\0") if p}
    require(paths and len(set(paths)) == len(paths), "allowlist-invalid")
    for rel in paths:
        path = Path(rel)
        require(not path.is_absolute() and path.as_posix() == rel
                and rel in tracked and not rc.match_path(rel, manifest["exclude"])
                and not any(p in {".", ".."} for p in path.parts), "allowlist-path")
        source = repo / rel
        require(source.is_file() and not any(p.is_symlink() for p in (source, *source.parents)), "allowlist-file")
        require(not forbidden(rel) or export_path_reviewed(repo, rel, manifest)
                or rc.blank_env_example(rel, source.read_bytes()), "allowlist-path")
    return sorted(paths)


def excluded_paths(triage):
    return {item["path"] for item in triage if item.get("decision") == "exclude"}


def paths_for(repo, run, manifest):
    paths = (run / "public-export.txt").read_text().splitlines()
    excluded = excluded_paths(read_json(run / "triage.json")) if (run / "triage.json").exists() else set()
    return validate_paths(repo, [path for path in paths if path and path not in excluded], manifest)


def difference(paths, previous):
    return {"added": sorted(set(paths) - set(previous)), "removed": sorted(set(previous) - set(paths))}


def proposed_paths(repo, manifest):
    paths = sorted(os.fsdecode(p) for p in rc.git(repo, "ls-files", "-z").split(b"\0") if p)
    return [p for p in paths if not rc.match_path(p, manifest["exclude"])
            and (repo / p).is_file() and not any(parent.is_symlink() for parent in (repo / p, *(repo / p).parents))
            and (not forbidden(p) or export_path_reviewed(repo, p, manifest))]


def head_blobs(repo, head, paths):
    blobs = rc.git(repo, "cat-file", "--batch", input="".join(head + ":" + path + "\n" for path in paths).encode())
    found = {}
    for path in paths:
        header, blobs = blobs.split(b"\n", 1)
        require(not header.endswith(b" missing"), "source-dirty")
        size = int(header.split()[2])
        found[path], blobs = blobs[:size], blobs[size + 1:]
    return found


def committed_source(repo, export, paths):
    head = rc.git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = rc.git(repo, "rev-parse", "--verify", head + "^{tree}").decode().strip()
    wanted = set(paths)

    def listing(root, commit):
        entries = rc.git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
        return [e for e in entries if e and os.fsdecode(e.split(b"\t", 1)[1]) in wanted]

    staged = [p for p in rc.git(repo, "diff-index", "--cached", "--name-only", "-z", head).split(b"\0")
              if p and os.fsdecode(p) in wanted]
    require(not staged and listing(repo, head) == listing(export, "HEAD"), "source-dirty")
    for path, data in head_blobs(repo, head, paths).items():
        require(data == (export / path).read_bytes(), "source-dirty")
    return {"source_head": head, "source_tree": tree}


class ValueScanner(rc.Scanner):
    def __init__(self, *args):
        super().__init__(*args)
        self.values = {}

    def add(self, scope, category, kind, path, line=0, value=b"", *rest, **options):
        item = super().add(scope, category, kind, path, line, value, *rest, **options)
        if isinstance(value, str) and value:
            self.values.setdefault(item["fingerprint"], value)
        return item


def finding_values(terms, private_repos, path, raw):
    scanner = ValueScanner(terms, private_repos)
    scanner.file(raw, "tree", path)
    return scanner.values


def named_in_checks(manifest, path):
    names = {item.get("file", "README.md") for item in manifest["quickstart"]}
    names |= {part for item in [*manifest["quickstart"], *manifest["checks"]] for arg in item["argv"]
              if isinstance(arg, str) for part in (arg, arg.partition("=")[2])}
    names = {os.path.normpath(name) for name in names if isinstance(name, str) and name}
    return any(path == name or path.startswith(name + "/") for name in names if name not in {".", ".."} and not name.startswith("../"))


def guarded(manifest, path):
    return bool(rc.protected(path) or ATTRIBUTION_FILE.search(path) or named_in_checks(manifest, path))


def env_keys(repo):
    keys = set()
    for path in repo.glob(".env*"):
        if (path.name == ".env" or path.name.startswith(".env.")) and path.is_file() and not path.is_symlink():
            keys |= set(re.findall(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=", path.read_text(errors="replace")))
    return sorted(keys)


def sanitize(repo, run, manifest, terms, private_repos, paths):
    require(not (run / "approval.json").exists(), "run-approved")
    spec = run / "transforms.json"
    require(spec.is_file() and not spec.is_symlink(), "transforms-missing")
    transforms = read_json(spec)
    require(isinstance(transforms, list) and transforms, "transforms-schema")
    head = rc.git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tree = rc.git(repo, "rev-parse", "--verify", head + "^{tree}").decode().strip()
    modes = {os.fsdecode(path): meta.split()[0].decode() for meta, path in
             (entry.split(b"\t", 1) for entry in rc.git(repo, "ls-tree", "-r", "-z", "--full-tree", head).split(b"\0") if entry)}
    require(all(modes.get(path) in {"100644", "100755"} for path in paths), "source-dirty")
    files = {path: (modes[path], data) for path, data in head_blobs(repo, head, paths).items()}
    terms = rc.export_terms(terms, repo)
    changes = []
    for item in transforms:
        require(isinstance(item, dict) and set(item) - {"approve_protected", "holder"} == TRANSFORM_KEYS.get(item.get("op"))
                and ("holder" not in item or item["op"] == "add") and item.get("approve_protected", True) is True, "transforms-schema")
        if item["op"] == "add":
            require(isinstance(item["template"], str) and item["template"] in TEMPLATES, "transforms-schema")
            path, text = TEMPLATES[item["template"]]
        else:
            path = item.get("path", ".env.example")
        require(isinstance(path, str), "transforms-schema")
        protected = guarded(manifest, path)
        require(not protected or item.get("approve_protected") is True, "transform-protected")
        change = {"op": item["op"], "path": path, **({"approved_protected": True} if protected else {})}
        if item["op"] == "env-example":
            keys = env_keys(repo)
            require(keys, "env-keys-missing")
            files[path] = ("100644", "".join(key + "=\n" for key in keys).encode())
            change.update(keys=keys)
        elif item["op"] == "add":
            holder = item.get("holder")
            require(("{holder}" in text) == ("holder" in item), "transforms-schema")
            if "holder" in item:
                require(isinstance(holder, str) and 0 < len(holder) <= 200 and holder.isprintable(), "transforms-schema")
                text = text.replace("{holder}", holder)
                require(rc.root_licence(text) == item["template"], "transform-holder")
            require(path not in files, "transform-path")
            files[path] = ("100644", text.encode())
            change.update({key: item[key] for key in ("template", "holder") if key in item})
        else:
            require(path in files, "transform-path")
            mode, raw = files.pop(path)
            change["before_sha256"] = rc.sha256(raw)
            if item["op"] == "drop":
                changes.append(change)
                continue
            if item["op"] == "strip-metadata":
                stripped = rc.strip_metadata(raw)
                require(stripped is not None, "transform-not-image")
                require(rc.metadata_text(stripped, [rc.ARCHIVE_MAX_BYTES, rc.ARCHIVE_MAX_MEMBERS]) == (b"", set()), "transform-incomplete")
                files[path] = (mode, stripped)
            else:
                fingerprint, placeholder = item["fingerprint"], item["placeholder"]
                require(isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{16}", fingerprint)
                        and isinstance(placeholder, str) and 0 < len(placeholder) <= 200 and placeholder.isprintable(), "transforms-schema")
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise rc.AuditError("transform-not-text") from None
                value = finding_values(terms, private_repos, path, raw).get(fingerprint)
                require(value is not None and value in text, "transform-not-found")
                files[path] = (mode, text.replace(value, placeholder).encode())
                require(fingerprint not in finding_values(terms, private_repos, path, files[path][1]), "transform-incomplete")
                change.update(fingerprint=fingerprint, placeholder=placeholder, occurrences=text.count(value))
        change["after_sha256"] = rc.sha256(files[path][1])
        changes.append(change)
    staging = Path(tempfile.mkdtemp(prefix=".candidate-", dir=run))
    try:
        for path, (mode, data) in files.items():
            target = staging / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
            target.chmod(0o700 if mode == "100755" else 0o600)
        rc.index_paths(staging, sorted(files))
        record = {"schema_version": 1, "source_head": head, "source_tree": tree, "source_paths": paths,
                  "transforms_sha256": rc.sha256(rc.canonical_json(transforms)),
                  "candidate_tree": rc.git(staging, "rev-parse", "HEAD^{tree}").decode().strip(), "changes": changes}
        candidate = run / "candidate"
        require(not candidate.is_symlink(), "run-symlink")
        (run / "changes.json").unlink(missing_ok=True)
        if candidate.exists():
            shutil.rmtree(candidate)
        write_json(run / "changes.json", record)
        staging.rename(candidate)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return record


def scan_target(repo, run, paths, manifest):
    record, candidate = run / "changes.json", run / "candidate"
    if not record.exists() and not candidate.exists() and not candidate.is_symlink():
        return repo, paths, None
    require(record.is_file() and not record.is_symlink() and candidate.is_dir() and not candidate.is_symlink(),
            "candidate-incomplete")
    changes = read_json(record)
    spec = run / "transforms.json"
    head = rc.git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    require(spec.is_file() and not spec.is_symlink() and rc.sha256(rc.canonical_json(read_json(spec))) == changes["transforms_sha256"]
            and changes["source_head"] == head and changes["source_paths"] == paths, "candidate-stale")
    require(all(c.get("approved_protected") or not guarded(manifest, c["path"]) for c in changes["changes"]), "transform-protected")
    require(rc.git(candidate, "rev-parse", "HEAD^{tree}").decode().strip() == changes["candidate_tree"]
            and rc.git(candidate, "status", "--porcelain", "--untracked-files=all") == b"", "candidate-changed")
    return candidate, sorted(os.fsdecode(p) for p in rc.git(candidate, "ls-files", "-z").split(b"\0") if p), changes


def attempt_changes(attempt):
    path = attempt / "changes.json"
    return rc.sha256(path.read_bytes()) if path.is_file() else None


def preflight(repo, manifest, terms, private_repos, paths=None, *, use_cache=False, policy_digest=None):
    paths = proposed_paths(repo, manifest) if paths is None else paths
    with tempfile.TemporaryDirectory(prefix="preflight-") as tmp:
        snapshot = Path(tmp) / "source"
        rc.copy_tree(repo, snapshot, manifest, rc.Scanner(terms, private_repos), allowlist=paths, commit=False)
        validate_paths(snapshot, paths, manifest)
        cache = preflight_cache_directory(repo) if use_cache else None
        return preflight_snapshot(snapshot, manifest, terms, private_repos, cache=cache, policy_digest=policy_digest)


def preflight_cache_directory(source):
    try:
        directory = (Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
                     / "coldrelease" / "preflight-v1").expanduser().resolve()
        if directory.is_relative_to(source) or any((parent / ".git").exists()
                                                   for parent in (directory, *directory.parents)):
            return None
        return directory
    except OSError:
        return None


def preflight_cache_key(repo, manifest, terms, private_repos, policy_digest):
    files = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [name for name in dirs if name != ".git"]
        for name in names:
            path = Path(root) / name
            files.append((path.relative_to(repo).as_posix(), path.stat().st_mode & 0o777,
                          rc.sha256(path.read_bytes())))
    return rc.sha256(rc.canonical_json({
        "files": sorted(files), "policy_digest": policy_digest,
        "checker": [rc.sha256(Path(module).read_bytes()) for module in (rc.__file__, __file__)],
        "version": rc.VERSION, "runtime": [sys.version, sys.platform, locale.getpreferredencoding(False)],
        "policy": manifest, "terms": terms, "private_repos": private_repos,
    }))


def preflight_static(repo, scanner, manifest, cache, policy_digest):
    # Binary Bun conversion depends on an external executable, so always rerun it.
    key = None
    if cache is not None and not any(repo.rglob("bun.lockb")):
        key = preflight_cache_key(repo, manifest, scanner.terms, scanner.private_repos, policy_digest)
    entry = cache / (key + ".json") if key is not None else None
    if entry is not None:
        try:
            saved = read_json(entry)
            data = saved["data"]
            if (saved["key"] == key and saved["sha256"] == rc.sha256(rc.canonical_json(data))
                    and isinstance(data["license"], dict) and isinstance(data["findings"], list)):
                scanner.findings = data["findings"]
                return data["license"]
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            pass
    licensing = rc.license_audit(repo, scanner, manifest)
    rc.quality_audit(repo, scanner, manifest)
    if entry is not None:
        temporary = None
        try:
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = {"license": licensing, "findings": scanner.findings}
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(rc.canonical_json({"key": key, "data": data, "sha256": rc.sha256(rc.canonical_json(data))}))
            os.replace(temporary, entry)
        except OSError:
            pass
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
    return licensing


def preflight_snapshot(repo, manifest, terms, private_repos, *, cache=None, policy_digest=None):
    scanner = rc.Scanner(terms, private_repos, manifest["approvals"])
    licensing = preflight_static(repo, scanner, manifest, cache, policy_digest)
    project = rc.tomllib.loads((repo / "pyproject.toml").read_text()).get("project", {}) if (repo / "pyproject.toml").exists() else {}
    declared_tools = {"python", "python3", "pip", "pip3", *rc.verify_tools(manifest), *project.get("scripts", {})}
    for item in [*manifest["quickstart"], *manifest["checks"]]:
        argv = item.get("argv")
        require(isinstance(argv, list) and argv and all(isinstance(a, str) and "\0" not in a for a in argv), "command-schema")
        require(item.get("role", "quickstart") in rc.CHECK_ROLES, "command-role")
        executable = argv[0]
        local = repo / executable
        require(executable in declared_tools or shutil.which(executable) is not None
                or local.is_file() and local.resolve().is_relative_to(repo) and os.access(local, os.X_OK), "command-missing")
        if item in manifest["quickstart"]:
            doc = Path(item.get("file", "README.md"))
            require(not doc.is_absolute() and ".." not in doc.parts, "quickstart-document-path")
            lines = (repo / doc).read_text().splitlines()
            line = item.get("line", 0)
            require(type(line) is int and 1 <= line <= len(lines) and shlex.split(lines[line - 1]) == argv,
                    "quickstart-document-mismatch")
    unresolved = [f for f in scanner.findings if not f["reviewed"]]
    status = "FAIL" if any(f["kind"] not in rc.INCOMPLETE_KINDS for f in unresolved) else "INCOMPLETE" if unresolved else "PASS"
    return {"outcome": status, "findings": unresolved, "license": licensing,
            "dependency_verification": "deferred-to-export"}


def effective_manifest(repo, run, manifest, triage=None):
    obj = {**manifest, "approvals": list(manifest["approvals"])}
    triage = read_json(run / "triage.json") if triage is None else triage
    require(isinstance(triage, list), "triage-schema")
    for item in triage:
        require(isinstance(item, dict) and isinstance(item.get("path"), str), "triage-schema")
        path = repo / item["path"]
        require(path.resolve().is_relative_to(repo) and not path.is_symlink(), "triage-path")
        decision = item.get("decision", "approve")
        require(decision in REVIEW_DECISIONS, "triage-schema")
        if decision == "approve" and path.is_file() and item.get("file_sha256") == rc.sha256(path.read_bytes()):
            obj["approvals"].append({k: v for k, v in item.items() if k not in {"file_sha256", "decision"}})
    accepted = run / "release-check.json"
    if accepted.exists() or accepted.is_symlink():
        require(accepted.is_file() and not accepted.is_symlink(), "recipe-path")
        require(set(read_json(accepted)) <= set(RECIPE_KEYS), "recipe-schema")
        obj.update(recipe_of(rc.manifest_for(repo, accepted)))
    return obj


def recipe_of(manifest):
    return {key: manifest.get(key, []) for key in RECIPE_KEYS}


def parsed(path, parse):
    try:
        return parse(path) if path.is_file() else None
    except (OSError, ValueError, RecursionError):
        return None


def unittest_only(tests):
    files = [path for path in tests.rglob("test*.py") if path.is_file()] if tests.is_dir() else []
    def tests_in(node, kinds):
        return [item for item in node.body if isinstance(item, kinds) and item.name.startswith("test")]
    for path in files:
        try:
            tree = ast.parse(path.read_bytes())
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False
        imported = any(isinstance(node, ast.ImportFrom) and node.module == "unittest" and node.level == 0
                       and any(alias.name == "TestCase" and alias.asname is None for alias in node.names)
                       for node in tree.body)
        def test_case(node):
            return any(ast.dump(base) == ast.dump(ast.parse("unittest.TestCase", mode="eval").body)
                       or imported and isinstance(base, ast.Name) and base.id == "TestCase" for base in node.bases)
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
        packaged = all((tests / folder / "__init__.py").is_file() for folder in path.relative_to(tests).parents[:-1])
        if (not packaged or tests_in(tree, (ast.FunctionDef, ast.AsyncFunctionDef))
                or any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "load_tests" for node in tree.body)
                or any(tests_in(node, ast.AsyncFunctionDef) for node in classes)
                or any(node.name.startswith("Test") and not test_case(node) for node in classes)
                or not any(test_case(node) and tests_in(node, ast.FunctionDef) for node in classes)):
            return False
    return bool(files)


def propose_recipe(repo):
    pyproject = parsed(repo / "pyproject.toml", lambda p: rc.tomllib.loads(p.read_text()))
    package = parsed(repo / "package.json", read_json)
    makefile = (repo / "Makefile").read_text(errors="replace") if (repo / "Makefile").is_file() else ""
    checks, tools, starters = [], [], []
    if pyproject is not None:
        starters += PYTHON_INSTALLS
        runner = (["unittest", "discover", "-s", "tests", "-q"]
                  if "pytest" not in pyproject.get("tool", {}) and unittest_only(repo / "tests") else ["pytest", "-q"])
        checks.append({"role": "tests", "argv": ["python", "-m", *runner]})
    if isinstance(package, dict):
        tools += ["node", "npm"]
        starters += NPM_INSTALLS
        scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
        for name, (role, argv) in NPM_SCRIPTS.items():
            if isinstance(scripts.get(name), str) and "no test specified" not in scripts[name]:
                checks.append({"role": role, "argv": argv})
    if re.search(r"(?m)^test\s*:(?!=)", makefile):
        tools.append("make")
        checks.append({"role": "tests", "argv": ["make", "test"]})
    names = {*(pyproject or {}).get("project", {}).get("scripts", {})}
    quickstart, fenced = [], False
    lines = (repo / "README.md").read_text(errors="replace").splitlines() if (repo / "README.md").is_file() else []
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        try:
            argv = shlex.split(line) if fenced else []
        except ValueError:
            continue
        if argv and (any(argv[:len(start)] == start for start in starters) or argv[0] in names):
            quickstart.append({"file": "README.md", "line": number, "argv": argv})
    return {"quickstart": quickstart, "checks": checks, "verify_tools": tools}


def receipt_args(args, manifest):
    return argparse.Namespace(denylist=args.denylist, private_repo=args.private_repo,
                              verify=args.verify, timeout=args.timeout, manifest=manifest)


EVIDENCE_CAUSES = {"verification-not-configured": "recipe_missing", "verify-tool-missing": "tool_missing",
                   "verify-backend-unavailable": "runner_unavailable", "venv-creation-failed": "setup_failure"}


def source_name(repo, remote):
    cloned = repo.parent / "source.json"
    if remote is None and repo.is_relative_to(runs_root()) and cloned.is_file():
        remote = read_json(cloned).get("url")
    try:
        url = remote or rc.git(repo, "remote", "get-url", "origin").decode().strip()
    except rc.AuditError:
        return None
    match = rc.GITHUB_REPOSITORY.fullmatch(url) if isinstance(url, str) else None
    return match and match[1]


def write_evidence(attempt, report, manifest, name):
    if name is None:
        return
    items = [*manifest["quickstart"], *manifest["checks"]]
    verification = report["verification"]
    rows = verification["commands"]
    steps = [{"step": f"{row['role']} {row['step']}", "command": shlex.join(items[row["step"] - 1]["argv"]),
              "status": "fail" if row["exit_code"] else "pass", "duration_ms": 0, "inputs_hash": None,
              **({"failing_excerpt": f"exit {row['exit_code']}"} if row["exit_code"] else {})} for row in rows]
    failed = [row for row in rows if row["exit_code"]]
    kinds = sorted({f["kind"] for f in report["findings"] if f["scope"] == "verification"})
    detail = ", ".join(kinds) or "verification " + verification["status"]
    if failed and failed[0]["exit_code"] == 124:
        failure = {"class": "harness", "cause": "timeout", "detail": detail}
    elif failed:
        failure = {"class": "product", "cause": "test_failure" if failed[0]["role"] == "tests" else "behavior_mismatch", "detail": detail}
    elif verification["status"] == "pass" and steps and not any(
            f["scope"] == "verification" and f["category"] == "quality" for f in report["findings"]):
        failure = None
    else:
        cause = next((EVIDENCE_CAUSES[k] for k in kinds if k in EVIDENCE_CAUSES), "unknown" if steps else "empty_run")
        failure = {"class": "harness", "cause": cause, "detail": detail}
    receipt = read_json(attempt / "receipt.json")
    record = {"schema_version": 1, "run_id": attempt.parent.parent.name + "/" + attempt.name,
              "repo": {"name": name, "commit": receipt["export_head"]},
              "model": {"provider": "unknown", "model": "unknown", "effort": "unknown"},
              "steps": steps, "outcome": "pass" if failure is None else "fail" if failure["class"] == "product" else "incomplete",
              **({"failure": failure} if failure else {}),
              "time": {"waiting_ms": None, "setup_ms": None, "running_ms": None},
              "cost": {"usd": None, "input_tokens": None, "output_tokens": None},
              **({"procedure": {"recipe": "coldrelease", "commands": [shlex.join(item["argv"]) for item in items]}} if items else {}),
              "artifacts": [{"path": "receipt.json", "sha256": rc.sha256((attempt / "receipt.json").read_bytes()),
                             "description": "Coldrelease receipt: the release-safety verdict for this export"}]}
    write_json(attempt / "verify-evidence.json", record)


def validate_export(attempt, args):
    result = rc.validate_receipt(attempt / "receipt.json", attempt / "export", receipt_args(args, attempt / "manifest.json"))
    require(result["outcome"] == "PASS", result["reasons"][0] if result["reasons"] else "receipt-not-pass")
    receipt = read_json(attempt / "receipt.json")
    require(all(isinstance(receipt.get(k), str) for k in ("source_head", "source_tree")), "receipt-invalid")
    require(rc.git(attempt / "export", "rev-list", "--count", receipt["export_head"]).strip() == b"1", "export-ancestry")
    actual_paths = sorted(os.fsdecode(p) for p in rc.git(attempt / "export", "ls-tree", "-r", "--name-only", "-z", receipt["export_head"]).split(b"\0") if p)
    require(actual_paths == read_json(attempt / "allowlist.json"), "export-allowlist")
    return receipt


def scanner_binary(name, repo):
    binary = shutil.which(name)
    require(binary is not None, "scanner-missing")
    binary = str(Path(binary).resolve())
    require(not Path(binary).is_relative_to(repo), "scanner-inside-source")
    return binary


def scanner_argv(name, binary, root, clone, head):
    if name == "osv-scanner":
        offline = ["--offline", "--offline-vulnerabilities"] if rc.env_value("OSV_DB") else []
        return [binary, "scan", "source", "--recursive", "--no-ignore", "--allow-no-lockfiles", *offline,
                "--config", str(root / "osv-scanner.toml"), "--format", "json", "--output-file", str(root / "results.json"), str(clone)]
    if name == "bandit":
        return [binary, "--recursive", "--ini", str(root / "bandit.ini"), "--ignore-nosec", "--quiet",
                "--format", "json", "--output", str(root / "results.json"), str(clone)]
    if name == "gitleaks":
        return [binary, "git", str(clone), "--config", str(root / "gitleaks.toml"), "--gitleaks-ignore-path", str(root),
                "--ignore-gitleaks-allow", "--redact", "--no-banner", "--exit-code", "1",
                "--report-format", "json", "--report-path", str(root / "results.json"), "--log-opts=" + head]
    return [binary, "git", clone.as_uri(), "--branch", head, "--json", "--no-update",
            "--no-verification", "--no-ignore-tag", "--fail", "--fail-on-scan-errors", "--no-color"]


def require_supported_flags(name, binary, timeout):
    with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
        root = Path(tmp)
        env = rc.safe_environment(root / "home", Path("/usr/bin"))
        subcommand = {"osv-scanner": ["scan", "source"], "bandit": []}.get(name, ["git"])
        _, output = rc.command([binary, *subcommand, "--help"], root, env, timeout)
        argv = scanner_argv(name, binary, root, root / "export", "HEAD")
    text = output.decode(errors="replace")
    flags = sorted({arg.split("=")[0] for arg in argv if arg.startswith("--")})
    missing = [flag for flag in flags if not re.search(r"(?<![\w-])--(?:\[no-\])?" + re.escape(flag[2:]) + r"(?![\w-])", text)]
    if missing:
        raise rc.AuditError("scanner-unsupported", name + " lacks " + " ".join(missing))


def scan_export(attempt, name, receipt, timeout, repo):
    result = {"name": name, "export_head": receipt["export_head"], "export_tree": receipt["export_tree"],
              "outcome": "INCOMPLETE", "version": None}
    try:
        binary = scanner_binary(name, repo)
        with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
            root = Path(tmp)
            clone = root / "export"
            env = rc.safe_environment(root / "home", Path("/usr/bin"))
            code, version = rc.command([binary, "version" if name == "gitleaks" else "--version"], root, env, timeout)
            require(code == 0 and version.strip(), "scanner-version")
            result["version"] = version.decode(errors="replace").strip().splitlines()[0]
            if name in MINIMUM_VERSIONS:
                pattern, minimum = MINIMUM_VERSIONS[name]
                found = re.fullmatch(pattern, result["version"])
                require(found and tuple(map(int, found.groups())) >= minimum, "scanner-version")
            result["binary_sha256"] = rc.sha256(Path(binary).read_bytes())
            # Clone objects independently, then check out exactly the receipt commit.
            rc.git(root, "clone", "-q", "--no-local", "--no-checkout", str(attempt / "export"), str(clone))
            rc.git(clone, "checkout", "-q", "--detach", receipt["export_head"])
            require(rc.git(clone, "rev-parse", "HEAD^{tree}").decode().strip() == receipt["export_tree"], "scanner-tree")
            before = rc.inventory_digest(clone)
            if name == "gitleaks":
                (root / "gitleaks.toml").write_text('[extend]\nuseDefault = true\n')
            if name == "bandit":
                (root / "bandit.ini").write_text("[bandit]\n")
            if name == "osv-scanner":
                (root / "osv-scanner.toml").write_text("")
                database = rc.env_value("OSV_DB")
                result["database"] = "offline" if database else "online"
                if database:
                    require(Path(database).is_dir(), "scanner-database-missing")
                    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(Path(database).resolve())
            code, output = rc.command(scanner_argv(name, binary, root, clone, receipt["export_head"]), root, env, timeout)
            require(code != 124, "scanner-timeout")
            require(not (name == "osv-scanner" and b"no offline version of the OSV database" in output), "scanner-database-missing")
            require(code in ({0, 183} if name == "trufflehog" else {0, 1}), "scanner-exit-code")
            reported = None
            if name == "osv-scanner":
                report = root / "results.json"
                result["advisories"] = osv_advisories(read_json(report), clone)
                reported = bool(result["advisories"])
                finding = any(a["blocking"] for a in result["advisories"])
                result["output_sha256"] = rc.sha256(report.read_bytes())
            elif name == "bandit":
                report = root / "results.json"
                try:
                    data = read_json(report)
                except (OSError, ValueError) as error:
                    raise rc.AuditError("scanner-report") from error
                result["findings"] = bandit_findings(data, clone)
                reported, finding = bool(result["findings"]), False
                result["output_sha256"] = rc.sha256(report.read_bytes())
            elif name == "gitleaks":
                report = root / "results.json"
                rows = read_json(report)
                require(isinstance(rows, list), "scanner-report")
                finding = bool(rows)
                result["output_sha256"] = rc.sha256(report.read_bytes())
            else:
                rows = [json.loads(line) for line in output.splitlines() if line.strip()]
                require(rows and all(isinstance(row, dict) for row in rows), "scanner-report")
                require(any(row.get("msg") == "finished scanning" for row in rows), "scanner-incomplete")
                require(not any(str(row.get("level", "")).lower() in {"error", "fatal"} for row in rows), "scanner-error")
                finding = any("DetectorName" in row or "Raw" in row for row in rows)
                result["output_sha256"] = rc.sha256(output)
            require(rc.inventory_digest(clone) == before, "scanner-mutated")
            require((finding if reported is None else reported) or code == 0, "scanner-exit-code")
            result["outcome"] = "FAIL" if finding else "PASS"
            if finding:
                result["reason"] = "scanner-findings"
    except (rc.AuditError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        result["reason"] = str(error) if isinstance(error, rc.AuditError) else rc.failure_cause(error)
        if isinstance(error, rc.AuditError) and error.detail:
            result["detail"] = error.detail
    return result


def osv_advisories(data, clone):
    require(isinstance(data, dict) and isinstance(data.get("results"), list), "scanner-report")
    advisories = []
    for source in data["results"]:
        require(isinstance(source, dict) and isinstance(source.get("source"), dict)
                and isinstance(source["source"].get("path"), str) and isinstance(source.get("packages"), list), "scanner-report")
        path, base = Path(source["source"]["path"]).resolve(), clone.resolve()
        require(path.is_relative_to(base), "scanner-report")
        for row in source["packages"]:
            require(isinstance(row, dict) and isinstance(row.get("package"), dict)
                    and all(isinstance(row["package"].get(k), str) for k in ("name", "version", "ecosystem"))
                    and isinstance(row.get("groups"), list) and isinstance(row.get("vulnerabilities"), list), "scanner-report")
            package = row["package"]
            vulnerabilities = {}
            for vulnerability in row["vulnerabilities"]:
                require(isinstance(vulnerability, dict) and isinstance(vulnerability.get("id"), str)
                        and isinstance(vulnerability.get("affected", []), list), "scanner-report")
                vulnerabilities[vulnerability["id"]] = vulnerability
            require({i for group in row["groups"] if isinstance(group, dict) and isinstance(group.get("ids"), list)
                     for i in group["ids"]} == set(vulnerabilities), "scanner-report")
            for group in row["groups"]:
                require(isinstance(group, dict) and isinstance(group.get("ids"), list) and group["ids"]
                        and all(i in vulnerabilities for i in group["ids"])
                        and isinstance(group.get("max_severity", ""), str), "scanner-report")
                members = [vulnerabilities[i] for i in group["ids"]]
                fixed = sorted({str(event["fixed"]) for member in members for affected in member.get("affected", [])
                                if isinstance(affected, dict) and isinstance(affected.get("package"), dict)
                                and affected["package"].get("ecosystem") == package["ecosystem"]
                                and str(affected["package"].get("name", "")).casefold() == package["name"].casefold()
                                for span in affected.get("ranges") or [] if isinstance(span, dict)
                                for event in span.get("events") or [] if isinstance(event, dict) and "fixed" in event})
                try:
                    score = float(group.get("max_severity") or "nan")
                except ValueError:
                    score = float("nan")
                labels = {str((m.get("database_specific") or {}).get("severity", "")).upper() for m in members
                          if isinstance(m.get("database_specific") or {}, dict)}
                severe = score >= 7.0 or bool(labels & OSV_BLOCKING_SEVERITIES)
                advisories.append({"ids": sorted(group["ids"]), "aliases": sorted(map(str, group.get("aliases") or [])),
                                   "path": path.relative_to(base).as_posix(), "ecosystem": package["ecosystem"],
                                   "package": package["name"], "version": package["version"],
                                   "max_severity": group.get("max_severity", ""), "fixed": fixed,
                                   "blocking": severe and bool(fixed)})
    return advisories


def bandit_findings(data, clone):
    require(isinstance(data, dict) and isinstance(data.get("results"), list) and isinstance(data.get("errors"), list), "scanner-report")
    if data["errors"]:
        raise rc.AuditError("scanner-error", f"bandit could not scan {len(data['errors'])} files")
    findings, base = [], clone.resolve()
    for row in data["results"]:
        require(isinstance(row, dict) and isinstance(row.get("filename"), str)
                and all(isinstance(row.get(k), str) for k in ("test_id", "test_name"))
                and type(row.get("line_number")) is int and row["line_number"] > 0
                and all(isinstance(row.get(k), str) and row[k] in BANDIT_LEVELS for k in ("issue_severity", "issue_confidence")), "scanner-report")
        path = Path(row["filename"]).resolve()
        require(path.is_relative_to(base), "scanner-report")
        findings.append({"test_id": row["test_id"], "test_name": row["test_name"], "path": path.relative_to(base).as_posix(),
                         "line": row["line_number"], "severity": row["issue_severity"], "confidence": row["issue_confidence"]})
    return sorted(findings, key=lambda f: (f["path"], f["line"], f["test_id"]))


def scan_bindings(attempt, receipt, selection):
    results = read_json(attempt / "scanners.json")
    require(isinstance(results, list), "scanner-results")
    require(sorted(r["name"] for r in results) == sorted(selection) and len(set(selection)) == len(selection)
            and set(selection) <= set(SCANNERS), "scanner-selection")
    for result in results:
        require(result.get("outcome") == "PASS" and result.get("export_head") == receipt["export_head"]
                and result.get("export_tree") == receipt["export_tree"] and result.get("version"), "scanner-not-pass")
    return [{"name": r["name"], "result_sha256": rc.sha256(rc.canonical_json(r))} for r in sorted(results, key=lambda r: r["name"])]


def approved_baseline(repo, run):
    published = [p for p in other_runs(repo, run) if (p / "published.json").is_file() and (p / "approval.json").is_file()]
    for previous in sorted(published, key=lambda p: (p / "published.json").stat().st_mtime_ns, reverse=True):
        try:
            return read_json(previous / "approval.json")["allowlist"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return []


def target_value(repo, target):
    require(isinstance(target, str) and target and not target.startswith("-") and "\0" not in target, "target-invalid")
    remotes = rc.git(repo, "remote").decode().splitlines()
    if target in remotes:
        urls = rc.git(repo, "remote", "get-url", "--push", "--all", target).decode().splitlines()
        require(len(urls) == 1, "target-ambiguous")
        target = urls[0]
    require(target and not target.startswith("-"), "target-invalid")
    if ":" not in target:
        target = str((repo / target).resolve())
    require(":" in target or Path(target).is_absolute(), "target-invalid")
    return target


def public_head(repo, target, ref, timeout, credentials):
    rows = [row.split("\t") for row in rc.git(repo, "ls-remote", "--refs", target, ref, timeout=timeout, credentials=credentials).decode().splitlines()]
    named = [row for row in rows if row[-1] == ref]
    require(len(named) <= 1, "target-ambiguous")
    if not named:
        return None
    require(re.fullmatch(r"[a-f0-9]{40,64}", named[0][0]), "target-invalid")
    return named[0][0]


def reference_denylist(denylist):
    path = Path.home() / ".coldlocker" / "release-denylist.sha256"
    raw = denylist.read_bytes()
    entries = rc.load_terms(denylist)
    patterns = sum(isinstance(entry, dict) for entry in entries)
    used = {"path": str(denylist), "sha256": rc.sha256(raw), "terms": len(entries) - patterns, "patterns": patterns}
    described = "%s (sha256 %s, %d terms, %d patterns)" % (used["path"], used["sha256"], used["terms"], used["patterns"])
    try:
        reference = path.read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        rc.explain("this host has no reference denylist hash at %s; the owner writes the reference denylist's sha256 there. "
                   "Denylist given: %s" % (path, described))
        raise rc.AuditError("denylist-reference-missing") from None
    if not re.fullmatch(r"[a-f0-9]{64}", reference):
        rc.explain("%s must hold one sha256 (64 lowercase hex characters)" % path)
        raise rc.AuditError("denylist-reference-invalid")
    if used["sha256"] != reference:
        rc.explain("denylist %s is not this host's reference denylist (sha256 %s from %s); pass the reference file the export used"
                   % (described, reference, path))
        raise rc.AuditError("denylist-not-reference")
    return used


def check_branch_protection(target, ref, timeout):
    match = rc.GITHUB_REPOSITORY.fullmatch(target)
    if not match:
        return
    checks = GITHUB.admin_required_checks(match[1], ref.removeprefix("refs/heads/"), timeout)
    if checks:
        rc.explain("%s %s requires the status check(s) %s and applies them to admins, so GitHub will refuse the guarded push. "
                   "The owner chooses one way out: turn off 'Do not allow bypassing the above settings' for that branch "
                   "(the owner's push then lands and the checks run on it afterwards), or remove the required check. "
                   "Then rerun approve." % (match[1], ref, ", ".join(checks)))
        raise rc.AuditError("target-requires-checks")


def receipt_age_ok(receipt):
    created = datetime.fromisoformat(receipt["created_at"])
    age = datetime.now(timezone.utc) - created
    return created.tzinfo is not None and 0 <= age.total_seconds() <= RECORD_MAX_AGE_DAYS * 86400


def push_command(run, record):
    lease = [] if record.get("target_visibility") == "PRIVATE" else [
        "--force-with-lease=" + record["ref"] + ":" + (record["expected_public_head"] or "")]
    return ["git", "-C", str(run / "release.git"), "push", *lease, "public", record["release_head"] + ":" + record["ref"]]


def stage_release(attempt, run, receipt, target, ref, expected, timeout, credentials):
    head, body = release_commit(attempt / "export", receipt, expected)
    release = run / "release.git"
    shutil.rmtree(release, ignore_errors=True)
    rc.git(run, "init", "-q", "--bare", str(release))
    rc.git(release, "fetch", "-q", "--no-tags", str(attempt / "export"), "HEAD")
    require(rc.git(release, "rev-parse", "FETCH_HEAD").decode().strip() == receipt["export_head"], "export-ancestry")
    if body is not None:
        rc.git(release, "fetch", "-q", "--no-tags", target, ref, timeout=timeout, credentials=credentials)
        require(rc.git(release, "rev-parse", "FETCH_HEAD").decode().strip() == expected, "target-moved")
        require(rc.git(release, "hash-object", "-w", "-t", "commit", "--stdin", input=body).decode().strip() == head, "export-ancestry")
    rc.git(release, "update-ref", "refs/heads/release", head)
    rc.git(release, "remote", "add", "public", target)
    return head


def guard_records_root():
    return Path.home() / ".local" / "state" / "coldlocker" / "release-approvals"


def write_guard_record(target, head, record, attempt):
    match = GUARD_REMOTE.fullmatch(target)
    if not match:
        return None
    folder = guard_records_root() / match[1].removesuffix(".git").replace("/", "__") / head
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    files = {"receipt.json": (attempt / "receipt.json").read_bytes(), "approval.json": rc.canonical_json(record) + b"\n"}
    for name, data in files.items():
        path = folder / name
        try:
            write_bytes(path, data)
        except FileExistsError:
            require(path.read_bytes() == data, "guard-record-exists")
    return folder


def listing_reminder(target, source):
    name = re.split(r"[/:\\]", target.rstrip("/\\"))[-1].removesuffix(".git")
    try:
        text = source.expanduser().read_text(errors="replace")
    except OSError:
        return "Published " + name + ", but the listing source could not be read; check that it is listed."
    if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text, re.IGNORECASE):
        return None
    return "Published " + name + ", but it is not in the listing source; add it to the product listing."


OWNER_GUARDS = ("publication", "dispatch", "reminders", "keep_going", "public_push")


def owner_allows_public(target):
    path = Path.home() / ".coldlocker" / "guards.json"
    try:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return False
        config = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=rc.unique_json_object)
    except FileNotFoundError:
        return True
    except (OSError, ValueError, RecursionError):
        return False
    if not isinstance(config, dict) or set(config) - {"default", "repos"} or not isinstance(config.get("repos", {}), dict):
        return False
    repos = config.get("repos", {})
    if not all(re.fullmatch(r"[\w.-]+/[\w.-]+", name) for name in repos):
        return False
    for switches in [config.get("default", {})] + list(repos.values()):
        if not isinstance(switches, dict) or any(guard not in OWNER_GUARDS or not isinstance(value, bool)
                                                 for guard, value in switches.items()):
            return False
    match = re.fullmatch(r"(?:(?:https?|ssh)://(?:[^@/]+@)?|(?:[\w.-]+@)?)(?i:(?:ssh\.)?github\.com)(?::\d+)?[:/]"
                         r"([\w.-]+/[\w.-]+?)(?:\.git)?/?", target)
    default = config.get("default", {}).get("public_push", True)
    if not match:
        return default and all(switches.get("public_push", True) for switches in repos.values())
    repos = {name.lower(): switches for name, switches in repos.items()}
    return repos.get(match[1].lower(), {}).get("public_push", default)


def check_approval(record, args, repo, attempt, receipt):
    require(record["schema_version"] == 1 and set(record) <= APPROVAL_KEYS, "approval-invalid")
    require(record["receipt_sha256"] == receipt["receipt_sha256"]
            and record.get("source_head") == receipt["source_head"]
            and record.get("source_tree") == receipt["source_tree"], "approval-receipt")
    selection = [r["name"] for r in record["scanners"]]
    require(scan_bindings(attempt, receipt, selection) == record["scanners"], "approval-scanners")
    require(any(name in SECRET_SCANNERS for name in selection), "scanners-required")
    require(record["allowlist"] == read_json(attempt / "allowlist.json"), "approval-allowlist")
    require(record.get("recipe") == recipe_of(read_json(attempt / "manifest.json")), "approval-recipe")
    require(record.get("changes_sha256") == attempt_changes(attempt), "approval-changes")
    require(args.target is not None and target_value(repo, args.target) == record["target"], "approval-target")
    require(owner_allows_public(record["target"]), "owner-public-push-no")
    require(args.ref == record["ref"] and args.ref.startswith("refs/heads/"), "approval-ref")
    rc.git(repo, "check-ref-format", args.ref)
    expected = record["expected_public_head"]
    require(expected is None or isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{40,64}", expected), "approval-lease")
    release = release_commit(attempt / "export", receipt, expected)[0]
    require(record.get("release_head") == release, "approval-invalid")
    current = public_head(attempt / "export", record["target"], args.ref, args.timeout, args.use_git_credentials)
    require(current in (expected, release), "target-moved")
    return expected, current == release


def release_commit(export, receipt, parent):
    tree, rest = rc.git(export, "cat-file", "commit", receipt["export_head"]).split(b"\n", 1)
    require(tree == b"tree " + receipt["export_tree"].encode() and not rest.startswith(b"parent "), "export-ancestry")
    if parent is None:
        return receipt["export_head"], None
    body = tree + b"\nparent " + parent.encode() + b"\n" + rest
    return rc.git(export, "hash-object", "-t", "commit", "--stdin", input=body).decode().strip(), body


def gate_error(text):
    for line in reversed(text.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            return value["error"]
    return None


def final_gate(args, reports, target, manifest, head, tree):
    with tempfile.TemporaryDirectory(prefix="final-gate-") as tmp:
        clone = Path(tmp) / "published"
        try:
            rc.git(Path(tmp), "clone", "-q", "--no-local", "--branch", args.ref.removeprefix("refs/heads/"), target, str(clone),
                   timeout=args.timeout, credentials=args.use_git_credentials)
        except (rc.AuditError, subprocess.SubprocessError):
            return {"outcome": "INCOMPLETE", "report": None, "error": "published-clone-failed"}
        argv = [str(clone), "--denylist", str(args.denylist), "--reports", str(reports), "--verify",
                "--timeout", str(args.timeout), "--published-target", target, args.ref, "--manifest", str(manifest),
                "--expected-export", head, tree,
                *(flag for name in args.private_repo for flag in ("--private-repo", name)),
                *(["--use-git-credentials"] if args.use_git_credentials else [])]
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = rc.main(argv)
        sys.stderr.write(errors.getvalue())
    lines = output.getvalue().splitlines()
    summary = json.loads(lines[0]) if lines else {}
    error = gate_error(errors.getvalue() + "\n" + output.getvalue()) if code else None
    return {"outcome": {0: "PASS", 1: "FAIL"}.get(code, "INCOMPLETE"), "report": summary.get("report"),
            **({"error": error} if error else {}),
            **({"github_settings": summary["github_settings"]} if "github_settings" in summary else {})}


def anonymous_url(target):
    match = rc.GITHUB_REPOSITORY.fullmatch(target)
    if match:
        return "https://github.com/" + match[1] + ".git"
    parts = urllib.parse.urlsplit(target)
    require(parts.scheme in {"http", "https"} and "@" not in parts.netloc, "public-url-unknown")
    return target


@contextmanager
def anonymous_home():
    saved = {name: os.environ.get(name) for name in ("HOME", "CURL_HOME", "XDG_CONFIG_HOME", "NETRC")}
    with tempfile.TemporaryDirectory(prefix="anonymous-home-") as home:
        os.environ.update(HOME=home, CURL_HOME=home, XDG_CONFIG_HOME=home)
        os.environ.pop("NETRC", None)
        try:
            yield
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


class GitHub:
    def url(self, name):
        return "https://github.com/" + name + ".git"

    def gh(self, timeout, *argv):
        return subprocess.run(["gh", *argv], capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
                              env={**os.environ, "GH_HOST": "github.com"})

    def repositories(self, owner, timeout):
        result = self.gh(timeout, "repo", "list", owner, "--limit", "1000", "--json", "nameWithOwner", "--jq", ".[].nameWithOwner")
        require(result.returncode == 0, "github-unreadable")
        names = result.stdout.decode().split()
        require(all(GITHUB_NAME.fullmatch(name) and name.split("/")[0].lower() == owner.lower() for name in names), "github-unreadable")
        require(len(names) < 1000, "survey-limit")
        return names

    def admin_required_checks(self, name, branch, timeout):
        quoted = urllib.parse.quote(branch, safe="")
        result = self.gh(timeout, "api", "--hostname", "github.com", "--method", "GET", "repos/%s/branches/%s/protection" % (name, quoted))
        require(result.returncode == 0 or b"(HTTP 404)" in result.stderr, "github-unreadable")
        protection = json.loads(result.stdout) if result.returncode == 0 else {}
        enforced = (protection.get("enforce_admins") or {}).get("enabled") is True
        checks = list((protection.get("required_status_checks") or {}).get("contexts", [])) if enforced else []
        result = self.gh(timeout, "api", "--hostname", "github.com", "--method", "GET", "repos/%s/rules/branches/%s" % (name, quoted))
        require(result.returncode == 0, "github-unreadable")
        checks += [c["context"] for rule in json.loads(result.stdout) if rule.get("type") == "required_status_checks"
                   for c in rule.get("parameters", {}).get("required_status_checks", [])]
        return sorted(set(checks))

    def visibility(self, name, timeout):
        result = self.gh(timeout, "api", "--hostname", "github.com", "--method", "GET", "repos/" + name, "--jq", ".visibility")
        require(result.returncode == 0, "github-unreadable")
        value = result.stdout.decode().strip().upper()
        require(value in {"PUBLIC", "PRIVATE"}, "target-visibility")
        return value


GITHUB = GitHub()
GITHUB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.\.?$)[A-Za-z0-9_.-]+")


def flip_command(target):
    match = rc.GITHUB_REPOSITORY.fullmatch(target)
    return match and "gh repo edit " + match[1] + " --visibility public --accept-visibility-change-consequences"


def export_attempt(run):
    attempt_name = read_json(run / "export.json")["attempt"]
    require(isinstance(attempt_name, str) and Path(attempt_name).name == attempt_name and attempt_name.startswith("export-"), "export-invalid")
    attempt = run / "attempts" / attempt_name
    require(not any(p.is_symlink() for p in (attempt, attempt.parent)), "run-symlink")
    return attempt


def absolute(path, placeholder):
    return str(path.expanduser().resolve()) if path is not None else placeholder


def published_release(args, repo, run, done):
    record = read_json(run / "approval.json")
    attempts = run / "attempts"
    require(not attempts.is_symlink(), "run-symlink")
    matches = [a for a in sorted(attempts.glob("export-*")) if not a.is_symlink()
               and read_json(a / "receipt.json").get("receipt_sha256") == done["receipt_sha256"]]
    require(len(matches) == 1, "published-attempt-missing")
    receipt = read_json(matches[0] / "receipt.json")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    require(rc.sha256(rc.canonical_json(body)) == receipt["receipt_sha256"] == record["receipt_sha256"]
            and receipt["export_head"] == done["export_head"], "receipt-invalid")
    parent = record["expected_public_head"]
    head = release_commit(matches[0] / "export", receipt, parent)[0]
    require(done.get("published_head", head) == head and done.get("parent", parent) == parent, "receipt-invalid")
    return record, matches[0], receipt, head


def confirm_public(args):
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    require(args.run, "run-required")
    run = run_directory(repo, args.run)
    require((run / "published.json").is_file(), "not-published")
    with run_lock(run):
        return verify_public(args, repo, run)


def verify_public(args, repo, run):
    marker = run / "public-verified.json"
    marker.unlink(missing_ok=True)
    require(not args.use_git_credentials, "git-credentials-selection")
    require(args.denylist is not None, "policy-required")
    args.denylist = args.denylist.expanduser().resolve()
    require(not args.denylist.is_relative_to(repo), "denylist-inside-source")
    record, attempt, receipt, head = published_release(args, repo, run, read_json(run / "published.json"))
    args.verify = True
    validate_export(attempt, args)
    args.ref = record["ref"]
    target = anonymous_url(record["target"])
    with anonymous_home():
        gate = final_gate(args, run / "public-gate", target, attempt / "manifest.json", head, receipt["export_tree"])
    result = {"outcome": gate["outcome"], "run": args.run, "published_head": head, "public_gate": gate}
    if gate["outcome"] != "PASS":
        return {**result, "reasons": [gate.get("error") or "public-gate-not-pass"]}
    write_json(marker, {"published_head": head, "export_tree": receipt["export_tree"],
                        "receipt_sha256": receipt["receipt_sha256"], "report": gate["report"]})
    return {**result, "state": "public-verified"}


def status(args):
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    require(args.run, "run-required")
    run = run_directory(repo, args.run)
    audit =["--denylist", absolute(args.denylist, "DENYLIST"),
             *(flag for name in args.private_repo for flag in ("--private-repo", name)),
             *(["--timeout", str(args.timeout)] if args.timeout != 300 else [])]
    policy = [*audit, *(["--manifest", absolute(args.manifest, None)] if args.manifest else [])]
    credentials = ["--use-git-credentials"] if args.use_git_credentials else []

    def command(name, *extra, run_id=args.run):
        return shlex.join(["coldrelease", name, args.remote or str(repo), "--run", run_id, *policy, *extra])

    def target_flags(target, ref):
        return ["--verify", "--target", target, "--ref", ref, *credentials]

    def state(name, next_command, **extra):
        return {"outcome": "PASS", "run": args.run, "state": name, "next": next_command, **extra}

    if not run.is_dir():
        return state("new", command("preflight"))
    if (run / "published.json").is_file():
        record, attempt, receipt, head = published_release(args, repo, run, read_json(run / "published.json"))
        verified = run / "public-verified.json"
        if verified.is_file() and read_json(verified).get("published_head") == head:
            return state("public-verified", command("confirm-public"), published_head=head)
        clone = "PUBLISHED_CLONE"
        gate = shlex.join(["coldrelease", clone, *audit, "--reports", str(run / "final-gate"), "--verify",
                           "--published-target", record["target"], record["ref"],
                           "--manifest", str(attempt / "manifest.json"),
                           "--expected-export", head, receipt["export_tree"], *credentials])
        fetch = shlex.join(["git", "clone", "-q", "--branch", record["ref"].removeprefix("refs/heads/"), record["target"], clone])
        return state("published", fetch + " && " + gate, published_head=head)
    proposal, accepted = run / "proposed-release-check.json", run / "release-check.json"
    if proposal.is_file() and not accepted.exists():
        return state("recipe-proposed", shlex.join(["mv", str(proposal), str(accepted)]))
    if not (run / "plan.json").is_file():
        return state("preflighted", command("plan"))
    if not (run / "export.json").is_file():
        return state("planned", command("export", "--verify"))
    attempt = export_attempt(run)
    receipt = read_json(attempt / "receipt.json")
    if receipt["outcome"] != "PASS" or any(r["outcome"] != "PASS" for r in read_json(attempt / "scanners.json")):
        return state("export-not-pass", command("export", "--verify"), attempt=attempt.name)
    scanned = read_json(attempt / "scanners.json")
    rescan = command("plan", *(f for name in sorted({*(r["name"] for r in scanned), *SECRET_SCANNERS}) for f in ("--scanner", name)),
                     run_id="NEW_RUN")
    if args.remote:
        rescan = command("preflight", run_id="NEW_RUN") + " && " + rescan
    record_path = run / "approval.json"
    if not record_path.is_file():
        if not any(r["name"] in SECRET_SCANNERS for r in scanned):
            return state("exported", rescan, reasons=["scanners-required"])
        return state("exported", command("approve", *target_flags(args.target or "TARGET", args.ref)))
    record = read_json(record_path)
    if record["receipt_sha256"] != receipt["receipt_sha256"]:
        return state("approval-stale", command("preflight", run_id="NEW_RUN"))
    if not any(r["name"] in SECRET_SCANNERS for r in record["scanners"]):
        return state("approval-stale", rescan, reasons=["scanners-required"])
    return state("approved", shlex.join(push_command(run, record)),
                 then=command("publish", *target_flags(record["target"], record["ref"])))


def prune(args):
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    require(args.run, "run-required")
    require(args.keep is not None, "keep-required")
    run = run_directory(repo, args.run)
    require(run.is_dir(), "run-missing")
    with run_lock(run):
        attempts = run / "attempts"
        require(not attempts.is_symlink(), "run-symlink")
        found = sorted((a for a in attempts.iterdir() if a.is_dir() and not a.is_symlink()
                        and a.name.startswith(("check-", "export-"))),
                       key=lambda a: a.stat().st_mtime_ns, reverse=True) if attempts.is_dir() else []
        bound = {read_json(run / name)["receipt_sha256"] for name in ("approval.json", "published.json") if (run / name).is_file()}
        protected = {export_attempt(run).name} if (run / "export.json").is_file() else set()
        protected |= {a.name for a in found if (a / "receipt.json").is_file()
                      and read_json(a / "receipt.json").get("receipt_sha256") in bound}
        removed = [a for a in found if a.name not in protected][args.keep:]
        for attempt in removed:
            shutil.rmtree(attempt)
    return {"outcome": "PASS", "run": args.run, "removed": sorted(a.name for a in removed), "kept": sorted(
        a.name for a in found if a not in removed)}


def unresolved_findings(run):
    attempts = run / "attempts"
    require(not attempts.is_symlink(), "run-symlink")
    reports = [*run.glob("preflight-*.json"), *(attempts.glob("*/report.json") if attempts.is_dir() else [])]
    reports = [p for p in reports if p.is_file() and not p.is_symlink() and not p.parent.is_symlink()]
    require(reports, "review-needs-check")
    findings = read_json(max(reports, key=lambda p: p.stat().st_mtime_ns))["findings"]
    return sorted((f for f in findings if not f["reviewed"]), key=lambda f: (f["path"], f["line"], f["scope"], f["kind"]))


def ask(prompt):
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    return line.strip() if line else None


def replace_file(path, write):
    temp = path.with_name("." + path.name + ".review")
    temp.unlink(missing_ok=True)
    write(temp)
    temp.replace(path)


def review(args):
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    require(args.run, "run-required")
    run = run_directory(repo, args.run)
    require(run.is_dir(), "run-missing")
    with run_lock(run):
        triage_path = run / "triage.json"
        triage = read_json(triage_path) if triage_path.exists() else []
        require(isinstance(triage, list) and all(isinstance(item, dict) and isinstance(item.get("path"), str)
                                                 and item.get("decision", "approve") in REVIEW_DECISIONS for item in triage),
                "triage-schema")
        identity = ("scope", "kind", "path", "fingerprint")
        recorded = {tuple(item.get(k) for k in identity): item.get("decision", "approve") for item in triage}
        excluded = excluded_paths(triage)
        pending = [f for f in unresolved_findings(run) if f["path"] not in excluded]
        print(f"{len(pending)} unresolved finding(s). Answer a approve, e exclude the file from the export, "
              "f fix it in the source, s skip.", file=sys.stderr)
        added, resolved, answered = [], 0, set()
        for number, finding in enumerate(pending, 1):
            path = finding["path"]
            label = f"{number}. {finding['scope']} {path}:{finding['line']} {finding['kind']}"
            if path in excluded or tuple(finding[k] for k in identity) in answered:
                print(label + (" (excluded above)" if path in excluded else " (same decision as above)"), file=sys.stderr)
                resolved += 1
                continue
            earlier = recorded.get(tuple(finding[k] for k in identity))
            print(label + (f" (recorded: {earlier}, still unresolved)" if earlier else ""), file=sys.stderr)
            source = repo / path
            is_source = (not Path(path).is_absolute() and ".." not in Path(path).parts and source.is_file()
                         and not any(p.is_symlink() for p in (source, *source.parents)) and source.resolve().is_relative_to(repo))
            choice = ask("decision [a/e/f/s]: ")
            while choice is not None and (REVIEW_CHOICES.get(choice.lower()) is None
                                          or REVIEW_CHOICES[choice.lower()] in {"approve", "exclude"} and not is_source):
                print("approve and exclude need a source file path" if choice.lower() in REVIEW_CHOICES else "answer a, e, f or s",
                      file=sys.stderr)
                choice = ask("decision [a/e/f/s]: ")
            decision = REVIEW_CHOICES[choice.lower()] if choice is not None else None
            if decision == "approve":
                reason = ask("reason (do not repeat the value): ")
                while reason is not None and not (reason and reason.isprintable()):
                    reason = ask("reason (do not repeat the value): ")
                decision = decision if reason is not None else None
            if decision is None:
                break
            resolved += decision != "skip"
            answered.add(tuple(finding[k] for k in identity))
            if decision == "approve":
                added.append({"decision": "approve", **{k: finding[k] for k in identity}, "reason": reason,
                              "file_sha256": rc.sha256(source.read_bytes())})
            elif decision == "exclude":
                added.append({"decision": "exclude", "path": path})
                excluded.add(path)
            elif decision == "fix":
                added.append({"decision": "fix", **{k: finding[k] for k in identity}, "line": finding["line"]})
        if added:
            replaced = {tuple(item.get(k) for k in identity) for item in added}
            kept = [item for item in triage if tuple(item.get(k) for k in identity) not in replaced
                    and item.get("path") not in excluded_paths(added)]
            replace_file(triage_path, lambda temp: write_json(temp, [*kept, *added]))
    counts = {}
    for item in added:
        counts[item["decision"]] = counts.get(item["decision"], 0) + 1
    return {"outcome": "PASS", "run": args.run, "decisions": counts, "pending": len(pending) - resolved}


def export_passed(run, head):
    if not (run / "export.json").is_file():
        return False
    attempt = export_attempt(run)
    receipt = read_json(attempt / "receipt.json")
    return (receipt["outcome"] == "PASS" and receipt.get("source_head") == head
            and all(r["outcome"] == "PASS" for r in read_json(attempt / "scanners.json")))


def release(args):
    require(args.run, "run-required")
    require(args.verify, "verification-not-authorized")
    require(args.target is not None, "approval-target-required")
    require(args.denylist is not None, "policy-required")
    args.denylist = args.denylist.expanduser().resolve()
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    run = run_directory(repo, args.run)
    rerun = ", then rerun this release command"
    triage = shlex.join(["coldrelease", "review", str(repo), "--run", args.run]) + rerun

    def stage(name):
        result = workflow(argparse.Namespace(**{**vars(args), "command": name}))
        print("release: %s %s" % (name, result["outcome"]), file=sys.stderr)
        return result

    def stopped(result):
        if result["outcome"] != "FAIL":
            return result
        if result.get("outstanding_findings", 1):
            return {**result, "next": triage}
        return {**result, "next": "fix what the scanner lines above name (scanners.json in attempt "
                + result["attempt"] + "), commit" + rerun}

    head = rc.git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    planned = (run / "plan.json").is_file()
    exporting = not (run / "approval.json").is_file() and not export_passed(run, head)
    if not planned or exporting:
        require(planned or set(args.scanner) & set(SECRET_SCANNERS), "scanners-required")
        result = stage("preflight")
        recipe_only = {f["kind"] for f in result.get("findings", []) if not f["reviewed"]} <= RECIPE_FINDINGS
        if result["outcome"] != "PASS" and not (recipe_only and not planned):
            rc.print_fail_findings(result)
            return stopped(result)
    if not planned:
        result = stage("plan")
        if result["outcome"] != "PASS":
            return result
    proposal, accepted = run / "proposed-release-check.json", run / "release-check.json"
    if proposal.is_file() and not accepted.exists():
        return {"outcome": "INCOMPLETE", "run": args.run, "reasons": ["recipe-not-accepted"],
                "next": "review " + str(proposal) + ", accept it with " + shlex.join(["mv", str(proposal), str(accepted)]) + rerun}
    if not (run / "approval.json").is_file():
        if exporting:
            result = stage("export")
            if result["outcome"] != "PASS":
                return stopped(result)
        result = stage("approve")
        if result["outcome"] != "PASS":
            return result
    if not (run / "published.json").is_file():
        if read_json(run / "approval.json")["source_head"] != head:
            return {"outcome": "INCOMPLETE", "run": args.run, "reasons": ["source-changed"],
                    "next": "the source changed after approve; rerun this release command with a new --run"}
        result = stage("publish")
        if result["outcome"] != "PASS":
            return result
    record, attempt, receipt, published = published_release(args, repo, run, read_json(run / "published.json"))
    validate_export(attempt, args)
    gate = final_gate(argparse.Namespace(**{**vars(args), "ref": record["ref"]}), run / "final-gate", record["target"],
                      attempt / "manifest.json", published, receipt["export_tree"])
    print("release: final-gate " + gate["outcome"], file=sys.stderr)
    return gated({"outcome": "PASS", "run": args.run, "published_head": published}, gate, record["target"],
                 rc.Scanner(rc.load_terms(args.denylist), args.private_repo))


def status_text(result):
    if result["outcome"] != "PASS":
        return result["outcome"] + ": " + ", ".join(result["reasons"])
    lines = [result["state"] + (" " + result["published_head"] if "published_head" in result else "")]
    lines += ["reason: " + reason for reason in result.get("reasons", [])]
    return "\n".join([*lines, "next: " + result["next"], *(["then: " + result["then"]] if "then" in result else [])])


def workflow(args):
    repo = args.repo.expanduser().resolve()
    require(rc.git_repository(repo, "rev-parse", "--show-toplevel").decode().strip() == str(repo), "repository-root-required")
    require(rc.git(repo, "rev-parse", "--is-shallow-repository").strip() == b"false", "source-shallow")
    require(args.denylist is not None and args.timeout > 0, "policy-required")
    args.denylist = args.denylist.expanduser().resolve()
    require(not args.denylist.is_relative_to(repo), "denylist-inside-source")
    terms = rc.load_terms(args.denylist)
    manifest = rc.manifest_for(repo, args.manifest)
    scanner = rc.Scanner(terms, args.private_repo)
    run_id = args.run or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run = run_directory(repo, run_id)
    if args.command == "plan":
        require(not run.exists() or all(p.name.startswith(".") or p.name in {"triage.json", "public-export.txt", "release-check.json", "proposed-release-check.json", "source.json", "mirror.git", "source", "transforms.json", "changes.json", "candidate"} or p.name.startswith("preflight-") and p.suffix == ".json" for p in run.iterdir()), "run-exists")
        run.mkdir(parents=True, exist_ok=True, mode=0o700)
    else:
        require(args.command == "preflight" or args.run, "run-required")
        require(args.command != "sanitize" or not run.is_relative_to(repo), "run-state-inside-source")
        run.mkdir(parents=True, exist_ok=True, mode=0o700)
    with run_lock(run):
        if args.command in {"preflight", "sanitize"}:
            if (run / "triage.json").is_file():
                manifest = effective_manifest(repo, run, manifest)
            triage = read_json(run / "triage.json") if (run / "triage.json").is_file() else []
            paths = (paths_for(repo, run, manifest) if (run / "public-export.txt").exists()
                     else [p for p in proposed_paths(repo, manifest) if p not in excluded_paths(triage)])
            if args.command == "sanitize":
                record = sanitize(repo, run, manifest, terms, args.private_repo, paths)
                return {"outcome": "PASS", "run": scanner.safe_path(run_id), "changes_sha256": rc.sha256((run / "changes.json").read_bytes()),
                        "changes": [{"op": c["op"], "path": scanner.safe_path(c["path"])} for c in record["changes"]]}
            root, paths, _ = scan_target(repo, run, paths, manifest)
            policy_path = args.manifest or rc.default_manifest(repo)
            policy_digest = rc.sha256(rc.canonical_json([
                rc.sha256(args.denylist.read_bytes()),
                rc.sha256(policy_path.read_bytes()) if policy_path.exists() else None,
            ]))
            result = preflight(root, manifest, terms, args.private_repo, paths,
                               use_cache=not args.no_cache, policy_digest=policy_digest)
            write_json(run / ("preflight-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".json"), result)
            return {**result, "run": scanner.safe_path(run_id)}
        if args.command == "plan":
            previous = sorted((p for p in other_runs(repo, run)
                               if all((p / name).is_file() for name in ("public-export.txt", "plan.json", "triage.json"))),
                              key=lambda p: (p / "plan.json").stat().st_mtime_ns)
            triage_path = run / "triage.json"
            triage = read_json(triage_path) if triage_path.exists() else read_json(previous[-1] / "triage.json") if previous else []
            manifest = effective_manifest(repo, run, manifest, triage)
            proposal = run / "proposed-release-check.json"
            proposed = not manifest["quickstart"] and not manifest["checks"]
            if proposed:
                if not proposal.exists():
                    write_json(proposal, propose_recipe(repo))
                manifest = {**manifest, **recipe_of(rc.manifest_for(repo, proposal))}
            allowlist = run / "public-export.txt"
            paths = [p for p in (paths_for(repo, run, manifest) if allowlist.exists() else proposed_paths(repo, manifest))
                     if p not in excluded_paths(triage)]
            root, scan_paths, _ = scan_target(repo, run, paths, manifest)
            result = preflight(root, manifest, terms, args.private_repo, scan_paths)
            require(result["outcome"] == "PASS" or not proposed
                    or not any(f["kind"] in RECIPE_FINDINGS for f in result["findings"]),
                    "recipe-proposal-incomplete")
            require(result["outcome"] == "PASS", "preflight-not-pass")
            require(not any("\n" in p or "\r" in p for p in paths), "allowlist-path")
            for name in args.scanner:
                if shutil.which(name):
                    require_supported_flags(name, scanner_binary(name, repo), args.timeout)
            if not allowlist.exists():
                allowlist.write_text("".join(p + "\n" for p in paths))
            write_json(run / "plan.json", {"scanners": sorted(args.scanner)})
            if not triage_path.exists():
                write_json(triage_path, triage)
            baseline = (previous[-1] / "public-export.txt").read_text().splitlines() if previous else []
            return {"outcome": "PASS", "run": scanner.safe_path(run_id), "file_count": len(paths),
                    **({"recipe": "proposed-release-check.json"} if proposed else {}),
                    "allowlist_diff": {k: [scanner.safe_path(p) for p in v] for k, v in difference(paths, baseline).items()}}
        plan = read_json(run / "plan.json")
        require(isinstance(plan, dict) and isinstance(plan.get("scanners"), list)
                and all(isinstance(n, str) and n in SCANNERS for n in plan["scanners"])
                and len(set(plan["scanners"])) == len(plan["scanners"]), "scanner-selection")
        if args.command in {"check", "export"}:
            require(args.verify, "verification-not-authorized")
            manifest = effective_manifest(repo, run, manifest)
            require(not (run / "proposed-release-check.json").exists() or (run / "release-check.json").exists(),
                    "recipe-not-accepted")
            root, paths, changes = scan_target(repo, run, paths_for(repo, run, manifest), manifest)
            result = preflight(root, manifest, terms, args.private_repo, paths)
            require(result["outcome"] == "PASS", "preflight-not-pass")
            attempts = run / "attempts"
            require(not attempts.is_symlink(), "run-symlink")
            attempts.mkdir(exist_ok=True)
            attempt = Path(tempfile.mkdtemp(prefix=args.command + "-", dir=attempts))
            write_json(attempt / "manifest.json", manifest)
            rc.copy_tree(root, attempt / "export", manifest, scanner, allowlist=paths)
            validate_paths(attempt / "export", paths, manifest)
            require(all(not forbidden(path)
                        or rc.git(attempt / "export", "show", "HEAD:" + path) == (attempt / "export" / path).read_bytes()
                        for path in paths), "allowlist-path")
            source = committed_source(root, attempt / "export", paths)
            if changes is not None:
                source = {key: changes[key] for key in ("source_head", "source_tree")}
                write_json(attempt / "changes.json", changes)
            before = rc.inventory_digest(attempt / "export")
            terms = rc.export_terms(terms, repo)
            report = rc.audit(attempt / "export", terms, manifest, args.private_repo, True, attempt, args.timeout,
                              tool_exclusions=(repo, run), source=repo, allowlist=paths,
                              verify_backend=args.verify_backend, host_fallback=args.allow_host_fallback)
            rc.preserve_historical_attribution(repo, attempt / "export", report, terms)
            audited = rc.inventory_digest(attempt / "export")
            if audited != before:
                scanner.add("export", "quality", "candidate-mutated", ".")
            report["findings"].extend(scanner.findings)
            report.update(rc.outcome(report))
            if args.command == "export" and plan["scanners"]:
                for category in report["coverage"]["categories"]:
                    if category["category"] == "external scanners":
                        category.update(status="run after this report",
                                        detail=", ".join(plan["scanners"]) + " run on this export after this report; their outcomes are in scanners.json")
                    if category["category"] == "application security" and "bandit" in plan["scanners"]:
                        category.update(status="run after this report",
                                        detail="bandit checks the export's Python code after this report; its findings are report-only and listed in scanners.json")
            rc.write_reports(attempt, report)
            rc.write_receipt(attempt, attempt / "export", report, receipt_args(args, attempt / "manifest.json"), inventory=audited, source=source)
            write_evidence(attempt, report, manifest, source_name(repo, args.remote))
            receipt = read_json(attempt / "receipt.json")
            results = [scan_export(attempt, name, receipt, args.timeout, repo) for name in plan["scanners"]] if args.command == "export" else []
            write_json(attempt / "scanners.json", results)
            write_json(attempt / "allowlist.json", paths)
            status = report["outcome"]
            if any(r["outcome"] == "FAIL" for r in results):
                status = "FAIL"
            elif status == "PASS" and any(r["outcome"] != "PASS" for r in results):
                status = "INCOMPLETE"
            if args.command == "export":
                pointer = run / "export.json"
                pending = attempt / "export-pointer.json"
                write_json(pending, {"attempt": attempt.name})
                pending.replace(pointer)
            hint = rc.fingerprint_upgrade_hint([report])
            if hint:
                print(hint, file=sys.stderr)
            rc.print_fail_findings(report)
            for result in results:
                if result["outcome"] == "FAIL" and result["name"] == "osv-scanner":
                    ids = ", ".join(sorted({i for a in result["advisories"] if a["blocking"] for i in a["ids"]}))
                    print(f"dependencies: osv-scanner found fixable critical or high advisories in @export ({ids}); upgrade the affected packages and rerun export (see scanners.json)", file=sys.stderr)
                elif result["name"] == "bandit" and result.get("findings"):
                    ids = ", ".join(sorted({f["test_id"] for f in result["findings"]}))
                    print(f"appsec: bandit reported {len(result['findings'])} findings in @export ({ids}); report only, they do not block (see scanners.json)", file=sys.stderr)
                elif result["outcome"] == "FAIL":
                    print(f"secrets: {result['name']} found blockers in @export; remove secrets from the tree and history and rerun the scanner (see README)", file=sys.stderr)
                elif result["outcome"] == "INCOMPLETE":
                    print(f"scanner: {result['name']} INCOMPLETE ({result.get('detail') or result['reason']}); see scanners.json", file=sys.stderr)
            return {"outcome": status, "run": scanner.safe_path(run_id), "attempt": attempt.name,
                    "outstanding_findings": sum(not f["reviewed"] for f in report["findings"]),
                    "scanners": [{"name": r["name"], "outcome": r["outcome"]} for r in results]}
        attempt = export_attempt(run)
        denylist = reference_denylist(args.denylist) if args.command == "approve" else None
        receipt = validate_export(attempt, args)
        manifest = effective_manifest(repo, run, manifest)
        require(manifest == read_json(attempt / "manifest.json"), "recipe-changed")
        require(not excluded_paths(read_json(run / "triage.json")) & set(read_json(attempt / "allowlist.json")), "allowlist-changed")
        if args.command == "approve":
            require(args.target is not None, "approval-target-required")
            require(not (run / "approval.json").exists(), "approval-exists")
            require(args.ref.startswith("refs/heads/") and rc.git(repo, "check-ref-format", args.ref) == b"", "ref-invalid")
            target = target_value(repo, args.target)
            require(GUARD_REMOTE.fullmatch(target) or "github.com" not in target.lower(), "target-invalid")
            require(owner_allows_public(target), "owner-public-push-no")
            require(receipt_age_ok(receipt), "receipt-expired")
            source = read_json(run / "source.json")["url"] if (run / "source.json").is_file() else None
            require(not source or repository_key(target) not in {repository_key(source), repository_key(str(run / "mirror.git"))},
                    "target-is-source")
            paths = read_json(attempt / "allowlist.json")
            _, current, changes = scan_target(repo, run, paths_for(repo, run, manifest), manifest)
            require(current == paths, "allowlist-changed")
            require(changes == (read_json(attempt / "changes.json") if attempt_changes(attempt) else None), "candidate-changed")
            binding = scan_bindings(attempt, receipt, plan["scanners"])
            require(any(item["name"] in SECRET_SCANNERS for item in binding), "scanners-required")
            check_branch_protection(target, args.ref, args.timeout)
            github = GUARD_REMOTE.fullmatch(target)
            visibility = GITHUB.visibility(github[1].removesuffix(".git"), args.timeout) if github else None
            expected = public_head(attempt / "export", target, args.ref, args.timeout, args.use_git_credentials)
            head = stage_release(attempt, run, receipt, target, args.ref, expected, args.timeout, args.use_git_credentials)
            record = {"schema_version": 1, "receipt_sha256": receipt["receipt_sha256"],
                      "source_head": receipt["source_head"], "source_tree": receipt["source_tree"],
                      "scanners": binding, "target": target, "ref": args.ref,
                      "expected_public_head": expected, "release_head": head, "denylist": denylist,
                      "recipe": recipe_of(manifest),
                      "allowlist": paths, "allowlist_diff": difference(paths, approved_baseline(repo, run)),
                      **({"changes_sha256": attempt_changes(attempt)} if changes is not None else {}),
                      **({"target_visibility": visibility} if visibility else {})}
            push = push_command(run, record)
            denylist_text = scanner.safe_path("%(path)s sha256 %(sha256)s, %(terms)d terms, %(patterns)d patterns" % denylist)
            if not denylist_text.endswith(" patterns"):
                denylist_text = denylist["path"].replace("\n", "[newline]").replace("\r", "[return]").replace("\t", "[tab]") + (
                    " sha256 %(sha256)s, %(terms)d terms, %(patterns)d patterns" % denylist)
            summary = ("Approved %s for %s %s: export %s, release commit %s on public head %s; denylist %s; receipt valid until %s"
                       % (scanner.safe_path(run_id), scanner.safe_path(target), scanner.safe_path(args.ref), receipt["export_head"],
                          head, expected or "none (new ref)", denylist_text,
                          (datetime.fromisoformat(receipt["created_at"]) + timedelta(days=RECORD_MAX_AGE_DAYS)).isoformat()))
            result = {"outcome": "PASS", "run": scanner.safe_path(run_id), "approval": "ready",
                      "receipt_sha256": receipt["receipt_sha256"], "file_count": len(paths), "outstanding_findings": 0,
                      "target": scanner.safe_path(target), "ref": scanner.safe_path(args.ref),
                      "expected_public_head": expected, "release_head": head, "denylist": denylist,
                      "guard_record": GUARD_REMOTE.fullmatch(target) is not None, "push": push,
                      "next": shlex.join(push), "then": "coldrelease publish (same flags), on any host that has the run",
                      "scanners": [{**item, "outcome": "PASS", "export_head": receipt["export_head"]} for item in binding],
                      "allowlist_diff": {k: [scanner.safe_path(p) for p in v] for k, v in record["allowlist_diff"].items()}}
            require(owner_allows_public(target), "owner-public-push-no")
            try:
                write_json(run / "approval.json", record)
            except FileExistsError:
                raise rc.AuditError("approval-exists") from None
            try:
                write_guard_record(target, head, record, attempt)
            except BaseException:
                (run / "approval.json").unlink()
                raise
            with suppress(OSError):
                print(summary, file=sys.stderr)
            return result
        record_path = run / "approval.json"
        require(record_path.is_file(), "approval-missing")
        record = read_json(record_path)
        expected, landed = check_approval(record, args, repo, attempt, receipt)
        if not landed:
            raise rc.AuditError("release-not-pushed", "run the guarded push first: " + shlex.join(push_command(run, record)))
        head = record["release_head"]
        try:
            write_json(run / "published.json", {"export_head": receipt["export_head"], "receipt_sha256": receipt["receipt_sha256"],
                                                "parent": expected, "published_head": head})
        except FileExistsError:
            raise rc.AuditError("already-published") from None
        result = {"outcome": "PASS", "run": scanner.safe_path(run_id), "published_head": head}
        reminder = args.listing_source and listing_reminder(record["target"], args.listing_source)
        if reminder:
            result["reminder"] = scanner.safe_path(reminder)
        if args.command == "ship":
            gate = final_gate(args, run / "final-gate", record["target"], attempt / "manifest.json", head, receipt["export_tree"])
            gated(result, gate, record["target"], scanner)
        return result


def gated(result, gate, target, scanner):
    result.update(outcome=gate["outcome"], final_gate=gate)
    if gate["outcome"] == "PASS":
        flip = flip_command(target)
        result["next"] = (scanner.safe_path(flip) if flip else
                          "make the target public with its host, then run coldrelease confirm-public on this run")
    else:
        result["reasons"] = ["final-gate-not-pass"]
        result["next"] = ("do not make the target public; the export is on the still-private target, "
                          "so read the final gate report, fix the source and start a new run")
    return result


def non_negative_count(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise argparse.ArgumentTypeError("must be a whole number of attempts, 0 or more")
    return int(value)


def survey_targets(text, timeout):
    if match := re.fullmatch(r"([A-Za-z0-9-]{1,39})/\*", text):
        return [(name, GITHUB.url(name)) for name in GITHUB.repositories(match[1], timeout)]
    lines = [line.strip() for line in Path(text).expanduser().read_text().splitlines()]
    return [(line, line) for line in lines if line and not line.startswith("#")]


def survey(args):
    require(args.denylist is not None, "policy-required")
    scanner = rc.Scanner(rc.load_terms(args.denylist.expanduser()), args.private_repo)
    rows = []
    for label, source in survey_targets(args.repo, args.timeout):
        result = run_command(argparse.Namespace(**{**vars(args), "command": "preflight", "repo": source}))
        safe = scanner.safe_path(label)
        if re.search(r"://[^/@\s]*:[^/@\s]*@", label):
            safe = "[path-" + rc.fingerprint(label) + "]"
        rows.append({"repository": safe, "outcome": result["outcome"], "findings": result.get("findings", []),
                     "reasons": result.get("reasons", [])})
    require(rows, "survey-empty")
    outcome = "FAIL" if any(r["outcome"] == "FAIL" for r in rows) else "INCOMPLETE" if any(r["outcome"] == "INCOMPLETE" for r in rows) else "PASS"
    return {"outcome": outcome, "repositories": rows}


def survey_table(rows):
    def cell(text):
        return json.dumps(text, ensure_ascii=True)[1:-1].replace("|", "\\|")
    lines = ["| Repository | Outcome | Top blockers by category | Missing documents |", "| --- | --- | --- | --- |"]
    for row in rows:
        counts = {}
        for finding in row["findings"]:
            counts[finding["category"]] = counts.get(finding["category"], 0) + 1
        blockers = [f"{category} {count}" for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]
        missing = [f["path"] + (" limitations" if f["kind"] == "missing-limitations" else "")
                   for f in row["findings"] if f["kind"].startswith("missing-")]
        lines.append("| " + " | ".join(cell(text) for text in (
            row["repository"], row["outcome"], ", ".join(blockers + row["reasons"]) or "none", ", ".join(missing) or "none")) + " |")
    return "\n".join(lines)


def run_command(args):
    try:
        require(len(args.scanner) == len(set(args.scanner)) and (not args.scanner or args.command in {"plan", "release"}), "scanner-selection")
        require(not args.use_git_credentials or args.command in {"preflight", "survey", "approve", "publish", "ship", "status", "confirm-public", "release"},
                "git-credentials-selection")
        require(args.create is None, "create-not-supported")
        require(not args.json or args.command == "status", "json-selection")
        require(args.keep is None or args.command == "prune", "keep-selection")
        require(args.command != "ship" or args.verify, "verification-not-authorized")
        require(args.verify_backend == "host" or args.command in {"check", "export", "release"}, "verify-backend-selection")
        require(not args.allow_host_fallback or args.verify_backend == "coldbox", "host-fallback-selection")
        if args.command == "survey":
            require(args.run is None, "run-selection")
            return survey(args)
        args.repo, args.remote = resolve_source(args)
        handler = {"status": status, "prune": prune, "confirm-public": confirm_public, "review": review, "release": release}.get(args.command, workflow)
        return handler(args)
    except (rc.AuditError, OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, rc.AuditError) else "workflow-incomplete"
        result = {"outcome": "FAIL" if reason == "target-moved" else "INCOMPLETE", "ready": False, "reasons": [reason]}
        detail = error.detail if isinstance(error, rc.AuditError) else rc.failure_cause(error)
        if detail:
            result["detail"] = detail
        return result


def main(argv=None):
    parser = rc.PrivateParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS, help="approve: the record it writes on disk is the approval, even if its output "
                        "is lost; status shows whether a run has one (state approved)")
    parser.add_argument("repo", help="local checkout, or a remote to clone for preflight: OWNER/REPO, https://, ssh://, file:// or git@host:path; "
                        "survey takes OWNER/* (listed with gh) or a file with one such source per line")
    parser.add_argument("--run")
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--private-repo", action="append", default=[])
    parser.add_argument("--no-cache", action="store_true", help="Rerun preflight static checks without the local content cache")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--timeout", type=rc.positive_seconds, default=300)
    parser.add_argument("--verify-backend", choices=rc.VERIFY_BACKENDS, default="host",
                        help="check, export and release only: run verification on this host (default) or in a disposable Coldbox VM")
    parser.add_argument("--allow-host-fallback", action="store_true",
                        help="With --verify-backend coldbox: run on this host when Coldbox does not answer, instead of INCOMPLETE")
    parser.add_argument("--scanner", choices=SCANNERS, action="append", default=[])
    parser.add_argument("--target")
    parser.add_argument("--create", metavar="OWNER/NAME",
                        help="refused: creating and flipping a new public repository would bypass the publication guard")
    parser.add_argument("--ref", default="refs/heads/main")
    parser.add_argument("--use-git-credentials", action="store_true",
                        help="approve, publish, ship and release only (status repeats it): let target reads ask the credential helpers in your global git config; "
                             "with a remote source, preflight uses them to read-only clone it")
    parser.add_argument("--json", action="store_true", help="status only: print the state as JSON")
    parser.add_argument("--keep", type=non_negative_count,
                        help="prune only: keep this many newest unbound attempts; the approved, published and current export attempts always stay")
    parser.add_argument("--listing-source", type=Path, default=os.environ.get("COLDRELEASE_LISTING_SOURCE") or None,
                        help="After publish, remind when the published repository name is absent from this file")
    args = parser.parse_args(argv)
    if args.denylist is None and (denylist := rc.env_value("DENYLIST")):
        args.denylist = Path(denylist)
    os.umask(0o077)
    result = run_command(args)
    result["notice"] = NOTICE
    code = {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[result["outcome"]]
    with suppress(OSError):
        print_result(args, result)
    return code


def print_result(args, result):
    if args.command == "status":
        print(json.dumps(result, sort_keys=True) if args.json else status_text(result))
        return
    if args.command == "survey" and "repositories" in result:
        print(survey_table(result["repositories"]))
        print(NOTICE)
        return
    if args.command == "preflight":
        rc.print_fail_findings(result)
    if result.get("reminder"):
        print(result["reminder"], file=sys.stderr)
    if result.get("next"):
        print("Next, run this yourself: " + result["next"] if result["next"].startswith("gh ") else "Next: " + result["next"],
              file=sys.stderr)
    if result.get("then"):
        print("Then: " + result["then"], file=sys.stderr)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
