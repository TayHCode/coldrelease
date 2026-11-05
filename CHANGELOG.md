# Changelog

## Unreleased

- Renamed to Coldrelease: the package and CLI are now `coldrelease`, and the README leads with "is this agent-made repository safe to publish?". `release-check.json`, the `RELEASE_CHECK_*` variables and report paths are unchanged.

- Stop with INCOMPLETE, exit 2, `not-repository-root` and a plain stderr reason when the legacy CLI is pointed at a subfolder of another Git repository, instead of silently auditing the parent repository.

- Name the cause of every unexpected INCOMPLETE, in the legacy CLI and the workflow commands, with a safe `detail` (exception class, plus the errno name for OS errors or the git subcommand for failed git calls); it never includes exception text, paths or file contents.

- Print one stderr hint per mismatched binding when `--validate-receipt` returns `receipt-stale`; JSON and exit codes are unchanged.

- Personal and media approvals that carry `classification: "false-positive"` now need a written reason and the exact line and source bytes (`source_sha256`), so a reviewed false positive clears only that one finding and a changed file invalidates it.

- Explain rejected `--validate-receipt` inputs (missing, unreadable, non-JSON, incomplete or tampered receipts, bad export folder) and an existing `--export` destination with one plain stderr line that never echoes paths or values; JSON, reason codes and exit codes are unchanged.

- Stop with INCOMPLETE, exit 2 and a plain reason when an explicit `--manifest` file does not exist, instead of auditing with an empty manifest; a missing default `release-check.json` stays optional.

- Explain unusable report folders with safe INCOMPLETE JSON, exit 2 and a plain reason without exposing supplied paths.

- Explain empty, malformed or wrongly shaped denylist files, broken, unreadable or missing manifest files and non-git repository paths with one plain stderr line that never echoes paths or terms; JSON errors and exit codes are unchanged.

- Explain missing repository paths and unreadable denylist files without echoing supplied paths; preserve JSON errors and exit codes.

- Explain missing workflow arguments and unknown commands without echoing supplied values.

- Reject non-integer and non-positive --timeout values up front with a plain reason that never echoes the supplied value.

- Explain invalid arguments on stderr without exposing supplied values; preserve the JSON error and exit code in both CLI parsers.

- Explain each unresolved finding on FAIL with its category, sanitized path and next action on stderr in audits and workflow verdicts; preserve stdout JSON, counts and exit codes.

- Add a plain-language `detail` (unknown or mistyped manifest key names and the expected types, never values) to the `manifest-schema` error in the CLI stderr line and the workflow JSON; the error code and exit code are unchanged.

- Report a `fingerprint_upgrades` list (kind, path, legacy and new fingerprint) and print one stderr hint when a source review matches only through its legacy full-mode fingerprint, so approvals can move to the umask-independent fingerprint; pass/fail is unchanged and no manifest is edited.

- Bind source-review fingerprints to the git-style executable bit instead of full file modes so a fresh clone reproduces the PASS under any umask; approvals made with full modes still match their exact original tree.

- Run workflow verification in the system temp directory so the verification
  workspace is never created inside the source repository.

- Report the specific `AuditError` code (for example `reports-inside-source`) in the
  legacy single-command CLI's stderr error instead of a bare `audit-incomplete`; other
  failures still print only `audit-incomplete`, and the exit code stays 2.

- Add the six-command Coldrelease workflow with stable local runs, exact tracked
  allowlists, byte-bound triage, optional external scanner results, human SSH
  approval, and exact-receipt publication with a signed destination lease.

- Treat GitHub ID+login noreply addresses and noreply@github.com as non-sensitive
  email matches. External denylist matches still block release.

- Add PASS/FAIL/INCOMPLETE outcomes and sorted reason codes to reports and stdout;
  retain `ready` as a deprecated PASS compatibility field and use outcome-based
  exit codes.
- Write an external `receipt.json` for exports, binding the inventory, recipe,
  policy and scanner; add read-only `--validate-receipt` with stale/invalid receipt
  reporting and document its hash-only trust limits.
- Ignore relative and empty verification PATH entries; reject executable paths and
  symlink targets inside the audited repository, original source, reports or export.
  Preserve these exclusions through export verification and block bin-directory escapes.
- Check every `package.json` outside `.git`, including nested and symlinked manifests.
  Require review for legacy `licenses`, all `pre`/`post` script keys and lifecycle
  hooks, `gypfile` and any `binding.gyp`; retain bounded, duplicate-free JSON checks.
- Accept dependency-free `package.json` projects only with bounded, duplicate-free
  JSON, no dependency declarations, install lifecycle commands, root or tracked
  lockfiles or `node_modules`; check declared licences against the root licence.
- Add manifest `verify_tools` to resolve up to eight declared executables on the
  caller's PATH and link them into the isolated verification bin directory. Missing
  or conflicting tools block verification without inheriting the caller's environment.
- Add a documented offline subprocess CLI proof for permissive, weak-copyleft and
  unlabelled dependency acceptance, with expected blockers and four audit bypasses.
- Preserve GPL/AGPL indications across independent metadata fields, classifiers and
  shipped license files, including placeholder expressions and conflicting labels.
- Match entire license labels and expression atoms, including WITH branches;
  incidental permissive or weak-copyleft names never establish acceptance.
- Restore permissive classifier and complete-license-text fallback for unrecognized
  free-text metadata while retaining strong-copyleft/proprietary blockers.
- Keep dependency-license evidence resolutions visible as reviewed findings;
  bind the digest to a plain license document and never erase contrary package text.
- Accept recognized permissive and weak-copyleft dependency licenses, with proper
  SPDX AND/OR evaluation; keep unavoidable GPL/AGPL and unknown licenses for review.
- Decode UTF-16/32 license files and inspect the whole text; a permissive SPDX
  header or reference wording cannot conceal a separate GPL/AGPL grant.
- Accept unlabelled packages only with recognizable permissive/weak-copyleft text
  in shipped license documents, and record file-based acceptance in verification reports.
  Block empty, binary, code, markup and unrecognized/proprietary evidence. Evaluate
  shipped SPDX declarations and distinguish LGPL text from its GPL references.
- Support dependency findings in existing approvals with a required reason and
  fingerprints binding exact package, version, metadata, installed license files and
  supplied dependency-license evidence. File detection uses actual license names or
  License-File declarations, rather than substrings in package paths.
- Add `--requirements` to list enforced files, README headings and manifest shape.
- Bound collected dependency data and report invalid metadata as an unwaivable
  coverage failure; clarify example manifests, repository-authored approvals and
  verification without a manifest.
- Detect missing venv support from wrapped ensurepip diagnostics and a same-interpreter
  import probe, with versioned installation advice in the finding itself. Keep a
  different cause and privacy-redacted error tail for other failures, preserving
  ordinary slash-separated wording such as Debian/Ubuntu.
- Redact entire absolute-path diagnostic suffixes, including spaces and embedded
  quotes, and document the bounded venv-output exception in JSON/Markdown reports.
