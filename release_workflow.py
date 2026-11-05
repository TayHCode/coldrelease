"""Local, human-approved release workflow over the Coldrelease audit engine."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
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

import release_check as rc

COMMANDS = ("preflight", "plan", "check", "export", "approve", "publish")
SCANNERS = ("gitleaks", "trufflehog")
NOTICE = "PASS means the declared checks passed; it does not guarantee safety."
NAMESPACE = "release-check-publish"


def read_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=rc.unique_json_object)


def write_json(path, value):
    with path.open("xb") as handle:
        handle.write(rc.canonical_json(value) + b"\n")


def require(condition, reason):
    if not condition:
        raise rc.AuditError(reason)


@contextmanager
def run_lock(run):
    lock = run / ".lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise rc.AuditError("run-locked") from None
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink()


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
        require(not forbidden(rel) or export_path_reviewed(repo, rel, manifest), "allowlist-path")
    return sorted(paths)


def paths_for(repo, run, manifest):
    paths = (run / "public-export.txt").read_text().splitlines()
    return validate_paths(repo, [path for path in paths if path], manifest)


def difference(paths, previous):
    return {"added": sorted(set(paths) - set(previous)), "removed": sorted(set(previous) - set(paths))}


def proposed_paths(repo, manifest):
    paths = sorted(os.fsdecode(p) for p in rc.git(repo, "ls-files", "-z").split(b"\0") if p)
    return [p for p in paths if not rc.match_path(p, manifest["exclude"])
            and (repo / p).is_file() and not any(parent.is_symlink() for parent in (repo / p, *(repo / p).parents))
            and (not forbidden(p) or export_path_reviewed(repo, p, manifest))]


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
                     / "release-check" / "preflight-v1").expanduser().resolve()
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
        if path.is_file() and item.get("file_sha256") == rc.sha256(path.read_bytes()):
            obj["approvals"].append({k: v for k, v in item.items() if k != "file_sha256"})
    return obj


def receipt_args(args, manifest):
    return argparse.Namespace(denylist=args.denylist, private_repo=args.private_repo,
                              verify=args.verify, timeout=args.timeout, manifest=manifest)


def validate_export(attempt, args):
    result = rc.validate_receipt(attempt / "receipt.json", attempt / "export", receipt_args(args, attempt / "manifest.json"))
    require(result["outcome"] == "PASS", result["reasons"][0] if result["reasons"] else "receipt-not-pass")
    receipt = read_json(attempt / "receipt.json")
    require(rc.git(attempt / "export", "rev-list", "--count", receipt["export_head"]).strip() == b"1", "export-ancestry")
    actual_paths = sorted(os.fsdecode(p) for p in rc.git(attempt / "export", "ls-tree", "-r", "--name-only", "-z", receipt["export_head"]).split(b"\0") if p)
    require(actual_paths == read_json(attempt / "allowlist.json"), "export-allowlist")
    return receipt


def scan_export(attempt, name, receipt, timeout, repo):
    result = {"name": name, "export_head": receipt["export_head"], "export_tree": receipt["export_tree"],
              "outcome": "INCOMPLETE", "version": None}
    try:
        binary = shutil.which(name)
        require(binary is not None, "scanner-missing")
        binary = str(Path(binary).resolve())
        require(not Path(binary).is_relative_to(repo), "scanner-inside-source")
        with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
            root = Path(tmp)
            clone = root / "export"
            env = rc.safe_environment(root / "home", Path("/usr/bin"))
            code, version = rc.command([binary, "version" if name == "gitleaks" else "--version"], root, env, timeout)
            require(code == 0 and version.strip(), "scanner-version")
            result["version"] = version.decode(errors="replace").strip()
            result["binary_sha256"] = rc.sha256(Path(binary).read_bytes())
            # Clone objects independently, then check out exactly the receipt commit.
            rc.git(root, "clone", "-q", "--no-local", "--no-checkout", str(attempt / "export"), str(clone))
            rc.git(clone, "checkout", "-q", "--detach", receipt["export_head"])
            require(rc.git(clone, "rev-parse", "HEAD^{tree}").decode().strip() == receipt["export_tree"], "scanner-tree")
            before = rc.inventory_digest(clone)
            if name == "gitleaks":
                config = root / "gitleaks.toml"
                config.write_text('[extend]\nuseDefault = true\n')
                report = root / "results.json"
                argv = [binary, "git", str(clone), "--config", str(config), "--gitleaks-ignore-path", str(root),
                        "--ignore-gitleaks-allow", "--redact", "--no-banner", "--exit-code", "1",
                        "--report-format", "json", "--report-path", str(report), "--log-opts=" + receipt["export_head"]]
                code, output = rc.command(argv, root, env, timeout)
                rows = read_json(report)
                require(isinstance(rows, list), "scanner-report")
                finding = bool(rows)
                result["output_sha256"] = rc.sha256(report.read_bytes())
                expected_codes = {0, 1}
            else:
                argv = [binary, "git", clone.as_uri(), "--branch", receipt["export_head"], "--json", "--no-update",
                        "--no-verification", "--no-ignore-tag", "--fail", "--fail-on-scan-errors", "--no-color"]
                code, output = rc.command(argv, root, env, timeout)
                rows = [json.loads(line) for line in output.splitlines() if line.strip()]
                require(rows and all(isinstance(row, dict) for row in rows), "scanner-report")
                require(any(row.get("msg") == "finished scanning" for row in rows), "scanner-incomplete")
                require(not any(str(row.get("level", "")).lower() in {"error", "fatal"} for row in rows), "scanner-error")
                finding = any("DetectorName" in row or "Raw" in row for row in rows)
                result["output_sha256"] = rc.sha256(output)
                expected_codes = {0, 183}
            require(rc.inventory_digest(clone) == before, "scanner-mutated")
            require(code in expected_codes and code != 124, "scanner-error")
            result["outcome"] = "FAIL" if finding else "PASS" if code == 0 else "INCOMPLETE"
    except (rc.AuditError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    return result


def scan_bindings(attempt, receipt, selection):
    results = read_json(attempt / "scanners.json")
    require(isinstance(results, list), "scanner-results")
    require(sorted(r["name"] for r in results) == sorted(selection) and len(set(selection)) == len(selection)
            and set(selection) <= set(SCANNERS), "scanner-selection")
    for result in results:
        require(result.get("outcome") == "PASS" and result.get("export_head") == receipt["export_head"]
                and result.get("export_tree") == receipt["export_tree"] and result.get("version"), "scanner-not-pass")
    return [{"name": r["name"], "result_sha256": rc.sha256(rc.canonical_json(r))} for r in sorted(results, key=lambda r: r["name"])]


def verify_signature(record, signature, trust, identity, timeout):
    require(trust is not None and identity and signature.is_file(), "approval-unsigned")
    raw = record.read_bytes()
    code = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(trust), "-I", identity,
                           "-n", NAMESPACE, "-s", str(signature)], input=raw,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode
    require(code == 0, "approval-signature")
    return json.loads(raw, object_pairs_hook=rc.unique_json_object)


def trusted_file(args, repo, run):
    require(args.allowed_signers is not None, "allowed-signers-required")
    trust = args.allowed_signers.expanduser().resolve()
    require(trust.is_file() and not trust.is_relative_to(repo) and not trust.is_relative_to(run), "allowed-signers-location")
    require(not os.access(trust, os.W_OK), "allowed-signers-writable")
    return trust


def approved_baseline(run, trust, identity, timeout):
    previous_runs = [p for p in run.parent.iterdir() if p != run and (p / "approval.json.sig").is_file()]
    for previous in sorted(previous_runs, key=lambda p: (p / "approval.json.sig").stat().st_mtime_ns, reverse=True):
        try:
            record = verify_signature(previous / "approval.json", previous / "approval.json.sig", trust, identity, timeout)
            require(record.get("schema_version") == 1 and record.get("identity") == identity, "approval-invalid")
            return record["allowlist"]
        except (rc.AuditError, OSError, ValueError, KeyError):
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


def public_head(repo, target, ref, timeout):
    rows = rc.git(repo, "ls-remote", "--refs", target, ref, timeout=timeout).decode().splitlines()
    require(len(rows) <= 1, "target-ambiguous")
    if not rows:
        return None
    sha, found = rows[0].split("\t")
    require(found == ref and re.fullmatch(r"[a-f0-9]{40,64}", sha), "target-invalid")
    return sha


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
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id)), "run-invalid")
    run = repo / ".coldrelease" / "runs" / run_id
    require(not any(p.is_symlink() for p in (run, *run.parents)), "run-symlink")
    if args.command == "plan":
        require(not run.exists() or all(p.name in {"triage.json", "public-export.txt"} or p.name.startswith("preflight-") and p.suffix == ".json" for p in run.iterdir()), "run-exists")
        run.mkdir(parents=True, exist_ok=True, mode=0o700)
    else:
        require(args.command == "preflight" or args.run, "run-required")
        run.mkdir(parents=True, exist_ok=True, mode=0o700)
    with run_lock(run):
        if args.command == "preflight":
            if (run / "triage.json").is_file():
                manifest = effective_manifest(repo, run, manifest)
            paths = paths_for(repo, run, manifest) if (run / "public-export.txt").exists() else None
            policy_path = args.manifest or repo / "release-check.json"
            policy_digest = rc.sha256(rc.canonical_json([
                rc.sha256(args.denylist.read_bytes()),
                rc.sha256(policy_path.read_bytes()) if policy_path.exists() else None,
            ]))
            result = preflight(repo, manifest, terms, args.private_repo, paths,
                               use_cache=not args.no_cache, policy_digest=policy_digest)
            write_json(run / ("preflight-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".json"), result)
            return {**result, "run": scanner.safe_path(run_id)}
        if args.command == "plan":
            previous = sorted((p for p in run.parent.iterdir() if p != run
                               and all((p / name).is_file() for name in ("public-export.txt", "plan.json", "triage.json"))),
                              key=lambda p: (p / "plan.json").stat().st_mtime_ns)
            triage_path = run / "triage.json"
            triage = read_json(triage_path) if triage_path.exists() else read_json(previous[-1] / "triage.json") if previous else []
            manifest = effective_manifest(repo, run, manifest, triage)
            allowlist = run / "public-export.txt"
            paths = paths_for(repo, run, manifest) if allowlist.exists() else proposed_paths(repo, manifest)
            result = preflight(repo, manifest, terms, args.private_repo, paths)
            require(result["outcome"] == "PASS", "preflight-not-pass")
            require(not any("\n" in p or "\r" in p for p in paths), "allowlist-path")
            if not allowlist.exists():
                allowlist.write_text("".join(p + "\n" for p in paths))
            write_json(run / "plan.json", {"scanners": sorted(args.scanner)})
            if not triage_path.exists():
                write_json(triage_path, triage)
            baseline = (previous[-1] / "public-export.txt").read_text().splitlines() if previous else []
            return {"outcome": "PASS", "run": scanner.safe_path(run_id), "file_count": len(paths),
                    "allowlist_diff": {k: [scanner.safe_path(p) for p in v] for k, v in difference(paths, baseline).items()}}
        plan = read_json(run / "plan.json")
        require(isinstance(plan, dict) and isinstance(plan.get("scanners"), list)
                and all(isinstance(n, str) and n in SCANNERS for n in plan["scanners"])
                and len(set(plan["scanners"])) == len(plan["scanners"]), "scanner-selection")
        if args.command in {"check", "export"}:
            require(args.verify, "verification-not-authorized")
            manifest = effective_manifest(repo, run, manifest)
            paths = paths_for(repo, run, manifest)
            result = preflight(repo, manifest, terms, args.private_repo, paths)
            require(result["outcome"] == "PASS", "preflight-not-pass")
            attempts = run / "attempts"
            require(not attempts.is_symlink(), "run-symlink")
            attempts.mkdir(exist_ok=True)
            attempt = Path(tempfile.mkdtemp(prefix=args.command + "-", dir=attempts))
            write_json(attempt / "manifest.json", manifest)
            rc.copy_tree(repo, attempt / "export", manifest, scanner, allowlist=paths)
            validate_paths(attempt / "export", paths, manifest)
            require(all(not forbidden(path)
                        or rc.git(attempt / "export", "show", "HEAD:" + path) == (attempt / "export" / path).read_bytes()
                        for path in paths), "allowlist-path")
            before = rc.inventory_digest(attempt / "export")
            report = rc.audit(attempt / "export", terms, manifest, args.private_repo, True, attempt, args.timeout,
                              tool_exclusions=(repo, run))
            rc.preserve_historical_attribution(repo, attempt / "export", report, terms)
            if rc.inventory_digest(attempt / "export") != before:
                scanner.add("export", "quality", "candidate-mutated", ".")
            report["findings"].extend(scanner.findings)
            report.update(rc.outcome(report))
            rc.write_reports(attempt, report)
            rc.write_receipt(attempt, attempt / "export", report, receipt_args(args, attempt / "manifest.json"))
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
                if result["outcome"] == "FAIL":
                    print(f"secrets: {result['name']} found blockers in @export; remove secrets from the tree and history and rerun the scanner (see README)", file=sys.stderr)
            return {"outcome": status, "run": scanner.safe_path(run_id), "attempt": attempt.name,
                    "outstanding_findings": sum(not f["reviewed"] for f in report["findings"]),
                    "scanners": [{"name": r["name"], "outcome": r["outcome"]} for r in results]}
        attempt_name = read_json(run / "export.json")["attempt"]
        require(isinstance(attempt_name, str) and Path(attempt_name).name == attempt_name and attempt_name.startswith("export-"), "export-invalid")
        attempt = run / "attempts" / attempt_name
        require(not any(p.is_symlink() for p in (attempt, attempt.parent)), "run-symlink")
        receipt = validate_export(attempt, args)
        manifest = effective_manifest(repo, run, manifest)
        require(manifest == read_json(attempt / "manifest.json"), "recipe-changed")
        trust = trusted_file(args, repo, run)
        require(not trust.is_relative_to(attempt / "export"), "allowed-signers-location")
        if args.command == "approve":
            require(args.target is not None and args.identity, "approval-target-required")
            require(args.ref.startswith("refs/heads/") and rc.git(repo, "check-ref-format", args.ref) == b"", "ref-invalid")
            target = target_value(repo, args.target)
            paths = read_json(attempt / "allowlist.json")
            require(paths_for(repo, run, manifest) == paths, "allowlist-changed")
            binding = scan_bindings(attempt, receipt, plan["scanners"])
            record = {"schema_version": 1, "receipt_sha256": receipt["receipt_sha256"],
                      "scanners": binding, "target": target, "ref": args.ref,
                      "expected_public_head": public_head(attempt / "export", target, args.ref, args.timeout), "identity": args.identity,
                      "allowlist": paths, "allowlist_diff": difference(paths, approved_baseline(run, trust, args.identity, args.timeout))}
            write_json(run / "approval.json", record)
            return {"outcome": "PASS", "run": scanner.safe_path(run_id), "approval": "prepared-unsigned",
                    "receipt_sha256": receipt["receipt_sha256"], "file_count": len(paths), "outstanding_findings": 0,
                    "target": scanner.safe_path(target), "ref": scanner.safe_path(args.ref),
                    "expected_public_head": record["expected_public_head"],
                    "scanners": [{**item, "outcome": "PASS", "export_head": receipt["export_head"]} for item in binding],
                    "allowlist_diff": {k: [scanner.safe_path(p) for p in v] for k, v in record["allowlist_diff"].items()}}
        record_path = run / "approval.json"
        record = verify_signature(record_path, run / "approval.json.sig", trust, args.identity, args.timeout)
        require(record["schema_version"] == 1 and record["identity"] == args.identity, "approval-invalid")
        require(record["receipt_sha256"] == receipt["receipt_sha256"], "approval-receipt")
        selection = [r["name"] for r in record["scanners"]]
        require(scan_bindings(attempt, receipt, selection) == record["scanners"], "approval-scanners")
        require(record["allowlist"] == read_json(attempt / "allowlist.json"), "approval-allowlist")
        require(args.target is not None and target_value(repo, args.target) == record["target"], "approval-target")
        require(args.ref == record["ref"] and args.ref.startswith("refs/heads/"), "approval-ref")
        rc.git(repo, "check-ref-format", args.ref)
        expected = record["expected_public_head"]
        require(expected is None or isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{40,64}", expected), "approval-lease")
        require(public_head(attempt / "export", record["target"], args.ref, args.timeout) == expected, "target-moved")
        # Validate again at the effect boundary, then push the receipt SHA, never mutable HEAD.
        validate_export(attempt, args)
        rc.git(attempt / "export", "-c", "core.hooksPath=/dev/null", "push", "--porcelain", "--no-follow-tags",
               "--force-with-lease=" + args.ref + ":" + (expected or ""), record["target"], receipt["export_head"] + ":" + args.ref,
               timeout=args.timeout)
        require(public_head(attempt / "export", record["target"], args.ref, args.timeout) == receipt["export_head"], "publish-unconfirmed")
        write_json(run / "published.json", {"export_head": receipt["export_head"], "receipt_sha256": receipt["receipt_sha256"]})
        return {"outcome": "PASS", "run": scanner.safe_path(run_id), "published_head": receipt["export_head"]}


def main(argv=None):
    parser = rc.PrivateParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--run")
    parser.add_argument("--denylist", type=Path, default=os.environ.get("RELEASE_CHECK_DENYLIST"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--private-repo", action="append", default=[])
    parser.add_argument("--no-cache", action="store_true", help="Rerun preflight static checks without the local content cache")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--timeout", type=rc.positive_seconds, default=300)
    parser.add_argument("--scanner", choices=SCANNERS, action="append", default=[])
    parser.add_argument("--allowed-signers", type=Path)
    parser.add_argument("--identity")
    parser.add_argument("--target")
    parser.add_argument("--ref", default="refs/heads/main")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        require(len(args.scanner) == len(set(args.scanner)) and (not args.scanner or args.command == "plan"), "scanner-selection")
        result = workflow(args)
    except (rc.AuditError, OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, rc.AuditError) else "workflow-incomplete"
        result = {"outcome": "INCOMPLETE", "ready": False, "reasons": [reason]}
        detail = error.detail if isinstance(error, rc.AuditError) else rc.failure_cause(error)
        if detail:
            result["detail"] = detail
    result["notice"] = NOTICE
    if args.command == "preflight":
        rc.print_fail_findings(result)
    print(json.dumps(result, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[result["outcome"]]


if __name__ == "__main__":
    raise SystemExit(main())
