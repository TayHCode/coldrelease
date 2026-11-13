# Changelog

## Unreleased

- The public export leaves out `.github/workflows/` and the test that checks those files, so the public repository has no CI until its self-hosted runners are safe for fork pull requests.
- **Breaking:** releases are approved by the owner's yes or no, not a signature. `approve` no longer takes `--identity`, `--allowed-signers` or `--scanner-waiver`, `status` no longer takes `--key`, and none of them, `publish`, `ship`, `release` or `confirm-public` signs or checks a signature. `approve` refuses when the owner's `"public_push"` switch in `~/.coldlocker/guards.json` says no or the file is invalid (`owner-public-push-no`), without a gitleaks or trufflehog PASS (`scanners-required`, no waiver), for a receipt older than 7 days (`receipt-expired`), for a denylist that is not the owner's reference denylist (`denylist-reference-missing`, `denylist-reference-invalid`, `denylist-not-reference`), and when GitHub requires checks on the target branch that bind admins (`target-requires-checks`, naming the two ways out). Only the target ref is read: other branches, tags and pull refs no longer block `approve` or `publish`. It builds the release commit (the export commit, or the export commit with the public head as its only parent) in the run's `release.git`, records the denylist's path, sha256 and counts, writes the record and receipt where the Coldlocker publication guard reads them, and prints one `git push --force-with-lease=REF:EXPECTED`. `publish` and `ship` no longer push: they read the target back and record the release, or return INCOMPLETE `release-not-pushed` with that push line. `ship --create` is refused (`create-not-supported`). `status` prints that push alone as `next` and `publish` as `then`, because the guard denies a push joined to another command. For a PRIVATE GitHub target `approve` records `target_visibility` and prints the push without a lease, which the guard requires for private pushes; Git still refuses a non-fast-forward. Before, a release needed an SSH signature with a trusted key, the target could hold no other ref, and `publish` pushed itself.

- New `coldrelease survey OWNER/*` (repositories listed read-only with `gh repo list`) or `coldrelease survey LIST_FILE` runs `preflight` on each source and prints a readiness table: outcome, unresolved findings counted by category or the INCOMPLETE reason, and missing documents. It never exports or publishes. Before, each repository needed its own `preflight` and the table was assembled by hand.

- A source path whose name is too long for the filesystem now returns INCOMPLETE `git-read-failed` with "repository path does not exist or is not a directory" on every Python version, and `OWNER/REPO` shorthand now accepts only GitHub-length names (owner up to 39 characters, repository up to 100), so a relative path such as `dir/` plus 256 characters stays local instead of being cloned from GitHub. Before, Python 3.11 to 3.13 returned `workflow-incomplete` with `OSError (ENAMETOOLONG)`, because `Path.exists()` raised there instead of returning false.

- The audit decodes asset metadata with the standard library and runs it through the same detectors as `file!metadata`: JPEG and PNG EXIF fields (author, software, image description and other text, GPS values, UTF-16 Windows `XP*` tags and Unicode user comments), PNG `tEXt`/`zTXt`/`iTXt` chunks and PDF Info strings (`/Author`, `/Creator`, `/Producer`, `/Title`, `/Subject`, `/Keywords`, literal or hex, UTF-16 included, also inside Flate object streams). Compressed PNG text over the archive limit is INCOMPLETE `archive-limit`, and a metadata block that cannot be decoded is INCOMPLETE `metadata-unreadable` without hiding the blocks after it. A new `strip-metadata` sanitize transform clears JPEG and PNG metadata in the candidate; other files stop with `transform-not-image`. Before, an EXIF author stored as UTF-16 or a compressed PNG comment was never seen.

- The repository manifest may be named `coldrelease.json`; when it is absent, `release-check.json` is still read. When both exist with different content, the run stops with `manifest-conflict` naming both files. Approvals are still signed in the `release-check-publish` namespace, and verification now also accepts approvals signed in `coldrelease-publish`.

- CI uses no GitHub-hosted runners. Every job in `test.yml`, `release.yml` and `verify.yml` runs on `[self-hosted, coldbox]`. Fork pull requests are skipped at the job level instead of falling back to `ubuntu-latest`, and `release.yml` has no `pull_request` trigger, so fork code never reaches Coldbox. Python comes from `astral-sh/setup-uv` (`uv venv --seed --python X`) instead of `actions/setup-python`, whose Ubuntu 26.04 builds stop with "CPU ISA level is lower than required" on Coldbox's x86-64-v2 hosts. Exporting these workflows to a public repo now needs a Coldbox runner registered there, and the export gate reports their `runs-on: [self-hosted, coldbox]` as `manual-review`. Before, the public `test` and `release` jobs and fork-PR `verify` runs used `ubuntu-latest`.

- The README now opens with the product promise (private repository in, clean public repository out) and the four-step workflow, for any developer open-sourcing a private repository. Before, it asked whether an agent-made repository was safe to publish.

- Root licences: a standard Apache-2.0, BSD-2-Clause, BSD-3-Clause (including the SPDX "copyright holder" wording) or ISC `LICENSE` now passes like MIT, and `pyproject.toml` and `package.json` licence metadata must name the same identifier. Root license files with two different licences block with `license-metadata-mismatch`. New sanitize transform `{"op": "add", "template": T}` writes a built-in LICENSE (with `"holder"` where the licence has a copyright line), CONTRIBUTING.md, SECURITY.md or `.github/ISSUE_TEMPLATE/bug_report.md` into the candidate and records it in `changes.json`. Before, only MIT passed and these documents had to be written by hand in the source.
- New `coldrelease sanitize SOURCE --run R` applies the run's reviewed `transforms.json` (`drop` a path, `replace` the value behind a finding fingerprint with a placeholder, `env-example` to write `.env.example` from the source's `.env*` keys with blank values) to a candidate copy built from committed content in the run state. The source is never written. It records `changes.json` (source commit, tree and allowlist, transforms digest, candidate tree, per-change digests). `preflight`, `plan`, `check` and `export` then scan and export the candidate, and stop with `candidate-stale` or `candidate-changed` when it no longer matches. The approval signs `changes_sha256`, and `publish`/`ship` refuse other changes with `approval-changes`. Transforms that touch licence, NOTICE or attribution files, or files named in the manifest's quickstart or checks, stop with `transform-protected` unless the entry has `"approve_protected": true`. A `.env.example` holding only `KEY=` lines no longer counts as a credential file. Before, every content fix had to be made in the source.
- New `coldrelease release SOURCE --run R --target T` runs preflight, plan, export, approve and `ship` in order, printing `release: STEP OUTCOME` for each, and stops only at a decision: findings return FAIL with `next` set to `coldrelease review`, a proposed recipe returns INCOMPLETE `recipe-not-accepted` with the `mv` that accepts it, and `ship` asks for the typed `yes` and signs with `--key`. Nothing is pushed before that `yes`. Rerunning it continues from the run's recorded state: it exports again when the source moved after a PASS export, refuses an unsigned approval of an older source (INCOMPLETE `source-changed`), and reruns the final gate on a published run. Before, the developer ran each step in turn.

- Owner-specific detectors now come from the denylist: a JSON denylist object may add `"patterns": [{"kind": ..., "pattern": ...}]`, matched like the built-in personal detectors (tree, paths, history, across line breaks) and bound into the receipt through the denylist digest. The fleet-only `fleet-cli` and `fleet-reference` detectors are no longer built in; their owner passes them as patterns. A stranger's repository that mentions those words now PASSes. A bad pattern (unknown shape, built-in or repeated kind, invalid regex, or one that can match zero characters) stops the run with `denylist-schema`.

- `--verify-backend coldbox` (on `coldrelease REPO --verify` and workflow `check`/`export`) runs the quickstart, the declared checks and the dependency metadata read in a disposable Coldbox VM through the `cold.exec/v0` interface (`coldbox version`, `vm up`, `vm exec`, `vm down`; `COLDRELEASE_COLDBOX` names another command). The report and the receipt's `verification_environment` record the VM image (its `PRETTY_NAME`) and the SHA-256 of everything the VM printed. When Coldbox is missing, busy, speaks another interface or gives no answer, verification is INCOMPLETE `verify-backend-unavailable` and nothing runs on this host; `--allow-host-fallback` runs it on the host instead and records the fallback and its reason. The default `host` backend is unchanged. Before, manifest commands could only run on the host.

- New `coldrelease confirm-public SOURCE --run R --identity I --allowed-signers F` closes the window between the final gate and the visibility change. After the flip it verifies the signed approval and published receipt, clones the target without credentials (a GitHub SSH target over its HTTPS URL; with an empty temporary `HOME` so `~/.netrc` cannot log in; other SSH targets and local paths are INCOMPLETE `public-url-unknown`) and runs the final gate with `--expected-export` from the signed receipt, reports under the run's `public-gate/`. On PASS it records `public-verified.json` and `status` shows `public-verified`. A target that moved after the gate returns FAIL `published-receipt-mismatch`, a still-private target INCOMPLETE `published-clone-failed`, and any non-PASS removes an earlier `public-verified.json`. `ship` and `confirm-public` gate results now name the gate's blocking `error`. Before, nothing checked the target again after the human made it public.

- The export scan (`--export` and workflow `check`/`export`) adds the commit author and committer names and emails, and the home-path usernames, found in the source history as private terms. A README that names the author now FAILs with `denylist` and no denylist entry; the terms are never printed, and an exact approval with a reason still accepts a public name such as a copyright holder. `[bot]` names, identities whose address is `noreply@…` (such as GitHub web merges), `users.noreply.github.com` emails (the author's name is still a term), exact matches of the export's own `Release Export` identity, generic home folders such as `runner` and `user`, and terms shorter than three characters are skipped. Before, names and usernames were caught only when listed in the denylist.

- `plan --scanner bandit` adds an application-security scan of the export's Python code with bandit 1.8.0 or later. Findings such as `subprocess` with `shell=True` or `verify=False` are report-only: the scanner PASSes, `scanners.json` records each finding's rule ID, path, line, severity and confidence, and export prints the rule IDs. `# nosec` comments and a `.bandit` file in the export cannot hide findings; unparseable files are INCOMPLETE `scanner-error`, an older bandit `scanner-version` and a missing one `scanner-missing`. Before, application security was not checked.

- `approve`, `publish` and `ship` require a secret scanner by default: they return INCOMPLETE `scanners-required` unless gitleaks or trufflehog PASSed on the export, or the owner approves with `approve --scanner-waiver`, which writes `"scanner_waiver": true` into the signed record and shows a `scanner waiver` line in the `ship` summary. `status` on such an export points to a new `plan` with both scanners. Before, an empty scanner selection approved and published.

- Run state no longer lives in the source checkout. New runs go to `$XDG_STATE_HOME/coldrelease/runs/<source>-<hash>/<run>/` (default `~/.local/state`, every folder mode 0700), so `preflight` through `ship` leave the source byte-identical, untracked files included, and no ignore rule is needed. A state folder inside the source returns INCOMPLETE `run-state-inside-source`. A run that already exists under the source's `.coldrelease/runs/` is still read and continued there, and old runs still count as plan and approval baselines. New `coldrelease prune SOURCE --run R --keep N` removes that run's oldest attempts beyond the newest N unbound ones; it never removes the current export attempt, the attempt bound by `approval.json` or `published.json`, the approval, its signature or other runs. Before, every attempt's full export copy stayed in the source forever.

- `plan --scanner osv-scanner` adds a dependency vulnerability scan of the export's lockfiles and manifests. Advisories with a fixed version and CVSS 7.0 or higher (or a HIGH or CRITICAL label) FAIL the export and block approval; `scanners.json` records each advisory's IDs, package, version, path, severity and fixed versions, and export prints the blocking IDs. `COLDRELEASE_OSV_DB` points it at an offline database; a missing tool is INCOMPLETE `scanner-missing` and a missing database INCOMPLETE `scanner-database-missing`. Before, known vulnerabilities were not checked.

- Interrupted runs recover. A `publish` whose push landed but whose acknowledgement or readback was lost can be rerun: when the target ref already holds the exact release commit computed from the signed receipt and parent, it pushes nothing and records `published.json`; before, it returned FAIL `target-moved` and the run was stranded. Any other head is still FAIL `target-moved`, and a run that already has `published.json` returns INCOMPLETE `already-published`. The run lock is now an OS `flock`, so a `.lock` left by a killed process no longer returns `run-locked` forever. Run markers are written to a temporary file and linked into place, so a crash or full disk can no longer leave a truncated `approval.json` or `published.json`.

- `publish` and `ship` keep an already-public branch's history. When the signed ref exists, they push, without force, one new commit with the receipt's exact tree whose only parent is the signed public head (`expected_public_head`); `published.json` records `published_head` and `parent`, and `ship`'s final gate and the gate printed by `status` expect that commit. A first publication still pushes the parentless export commit. A target head that moved after approval now returns FAIL `target-moved` (was INCOMPLETE) and pushes nothing. Before, every publish replaced the public branch with a fresh root commit.

- A `credential-url` finding can now take the same exact-source false-positive review as `entropy` and `assigned-secret`: `classification: "false-positive"`, a nonempty reason, and the exact `scope`, `kind`, `path`, `fingerprint`, `line`, `column` and whole-file `source_sha256`. A changed byte, another occurrence or a plain exact-match approval still blocks. Before, a URL with a placeholder password such as `<password>` could not be reviewed at all. The detector and every other explicit secret format are unchanged and still cannot be approved.

- Each `--private-repo` now also blocks its bare repository name as a whole word (not inside a longer name such as `name-extra`), in tree and history, so a placeholder owner (`o/name`) or a lone `name` no longer passes. Paths and venv diagnostics redact the bare name too.

- `COLDRELEASE_DENYLIST` and `COLDRELEASE_REPORTS` replace `RELEASE_CHECK_DENYLIST` and `RELEASE_CHECK_REPORTS`. The old names still work when the new one is unset and print a one-line deprecation notice to stderr; a flag or the new name wins without a notice. The default reports folder is now `~/.local/state/coldrelease` and the preflight cache `~/.cache/coldrelease/preflight-v1`; existing `release-check` folders are not moved or deleted, and `--reports` or either variable can still point at them. Receipts, `release-check.json` and the `release-check-publish` signature namespace are unchanged, so 0.1.0 receipts and signed approvals keep validating (`tests/test_coldrelease_names.py` checks a real 0.1.0 receipt).

- A built-in `fleet-reference` detector blocks the fleet's private Grok-based bot name in any capitalization, with a hyphen, an underscore, nothing or any whitespace (a line break included) between the two words, in tree files, paths and history. `check` and `export` FAIL on it at the exact line with no denylist term; before, a release passed unless the reviewer remembered to add the name. A repository that may name it publicly can accept it with an owner approval, which, as for an email address, covers that exact text in that one file.

- Block private fleet CLI references as `fleet-cli`: lowercase `cold` followed by one of its subcommands (`FLEET_CLI_COMMANDS` in `release_check.py`: model, launch, usage, verify, doctor, stalled, check, gh-token, gate, review, new-repo, update-skills), separated by any whitespace including a line break, in the tree and in history. A wrapped match is reported at its first line. Before, these commands passed with no finding. Public CLI names such as `coldrelease` stay clean. A public use can be approved by exact fingerprint like other personal findings.

- `.github/workflows/release.yml` builds the sdist and wheel on a `v*` tag push, runs `twine check --strict`, installs the wheel in a fresh venv, checks with `cmp` that it installs this checkout's modules byte for byte and that its `coldrelease --version` matches the tag, then runs the suite with that environment's interpreter. A tag push never uploads. Publishing needs a manual `workflow_dispatch` on the tag with `publish` set to true (default false), then the `pypi` environment's approval; it uploads with `pypa/gh-action-pypi-publish` over Trusted Publishing (OIDC, no token) with PEP 740 attestations. Like `test.yml`, it is skipped while the repository is private, and the engine tracks it so the public export keeps it.

- The README quickstart names every prerequisite (`git`, `python3-venv` and `openssh-client` on Debian/Ubuntu) and leads with the release workflow: one copy-paste demo goes from a fresh clone through `preflight`, `plan`, `export --verify`, `approve`, `ssh-keygen -Y sign` and `publish` to a local bare repository. It says where to add an approval when a reviewed finding FAILs. The flag-based audit moved to "Single-command audit"; `release-check.json` quickstart pins follow the new README lines. `tests/test_readme_quickstart.py` runs the demo blocks verbatim and requires five PASS outcomes and one published commit, so the README can't drift from a working flow.

## 0.1.0 - 2026-11-09

First tagged release (`v0.1.0` in the private engine repository).

- `coldrelease --version` (and `python3 release_check.py --version`) prints `coldrelease 0.1.0`, the version in `pyproject.toml`; before, it returned `invalid-arguments`.

- Issue templates and `--private-repo` work on any forge. The template check also accepts `.gitlab/issue_templates/*.md`, `.gitea/ISSUE_TEMPLATE/` and `.gitea/issue_template/`, and no longer counts a symlinked template. `--private-repo` drops the host from any HTTPS, `ssh://` or `user@host:` URL, so `https://gitlab.com/group/sub/proj.git` and `git@HOST:o/r.git` match HTTPS, SSH and bare-path references in the tree and history, as GitHub URLs already did.

- The final gate accepts `--expected-export EXPORT_HEAD EXPORT_TREE` and returns FAIL, exit 1, `published-receipt-mismatch` when the target holds a different commit or tree, before or after the scan. `ship` and the final-gate command printed by `status` pass the signed receipt's head and tree. Before, a target another writer replaced after `ship`'s publish readback passed the gate, and `ship` printed the visibility command for a tree with no signed receipt. `status` returns INCOMPLETE `receipt-invalid` instead of a final-gate command when the published receipt no longer matches its own digest, the approval or `published.json`. After publish, `status` prints the final-gate command only when `--identity` and `--allowed-signers` verify the approval signature; without them it returns `signed-unverified`, and a signature that does not verify is INCOMPLETE `approval-signature`.

- The final gate (`--published-target`) also checks the target's advertised `HEAD`: a detached `HEAD` at any commit other than the published branch's returns FAIL, exit 1, `published-extra-refs`, before and after the scan, and `approve` and `publish` return INCOMPLETE `target-extra-refs`. Before, `git ls-remote --refs` hid `HEAD`, so a target whose clean `main` passed could still serve private history to a plain clone. A `HEAD` pointing at the published branch still passes.

- The engine now tracks the public CI workflow `.github/workflows/test.yml` (GitHub-hosted `ubuntu-latest`, Python 3.11 and 3.13), so `plan` proposes it and the next export keeps public CI instead of deleting it. Its job is skipped while the repository is private, so the private repo spends no hosted-runner minutes; private CI stays on `verify.yml`, which must stay out of the public allowlist.

- `coldrelease status SOURCE --run ID` reads a run's files and prints its state (`planned`, `exported`, `approved-unsigned`, `approved-signed`, `published <sha>` and others) and the exact next command, such as the `ssh-keygen -Y sign` line or the final-gate command; `--json` prints JSON. It writes nothing, and prints a `publish` command only when the signature verifies against `--allowed-signers` and `--identity` for the run's current export.

- Clearer workflow errors, with the same outcomes and exit codes: a second `approve` on a run returns INCOMPLETE `approval-exists` instead of `workflow-incomplete`; the final gate on a clone with no checked-out commit returns INCOMPLETE `published-clone-empty` instead of `git-read-failed`; a run without `--reports` also prints the absolute `report.json` path to stderr; and each FAIL denylist finding prints the exact `approvals` entry to add if that text is meant to be public. Its `reason` is empty, so the entry matches nothing until you write why the text is public. Secret findings never get an approvals hint.

- A `quickstart` or `checks` entry in `release-check.json` can set `"timeout"` (whole seconds greater than 0) for that command instead of `--timeout`; `--requirements` lists the key and the receipt binds it with the manifest. A command killed at its limit now FAILs as `command-timeout`, and stderr names the role, the limit in seconds and its source; before, it showed only as `command-failed`.

- `coldrelease ship` is one owner command for signing, publishing and the final gate. It refuses a missing, already signed or stale `approval.json` before asking, shows the release summary, needs a typed `yes`, signs with `--key` through `ssh-keygen -Y sign`, runs `publish` unchanged, then runs the final gate on a fresh clone of the target (with `--use-git-credentials` when given). On a final-gate PASS it prints the exact `gh repo edit ... --visibility public` line for a GitHub target and never runs it.

- `approve`, `publish` and the final gate (`--published-target`) accept `--use-git-credentials`, so they can reach a private HTTPS target. Only the target lookups and the push use it, and they may ask only the `credential.helper` and `credential.<url>.helper` entries from your global git config; nothing else from that config reaches git. Without the flag nothing changes: global config stays isolated and a private target still returns `git-read-failed` or `published-ref-unavailable`.

- `plan --scanner` checks each installed scanner's `git --help` for every flag the adapter passes and returns INCOMPLETE `scanner-unsupported` with a `detail` naming the missing flags (trufflehog before 3.97.5 lacks `--no-ignore-tag`). Every FAIL or INCOMPLETE entry in `scanners.json` now records a `reason`, and export prints INCOMPLETE reasons to stderr; before, the cause was discarded. The workflow guide states the minimum versions: gitleaks 8.19.0 and trufflehog 3.97.5.

- The final gate (`--published-target`) returns FAIL, exit 1, `published-extra-refs` when the target holds any ref other than the published branch, including tags; before, a side branch carrying unexported private history still passed. `approve` and `publish` return INCOMPLETE `target-extra-refs` for the same target state, before anything is pushed.

- `publish` accepts `--listing-source FILE` (or `COLDRELEASE_LISTING_SOURCE`) and, after a successful push, adds a `reminder` to the PASS result and prints it to stderr when the published repository name is not in that file; the outcome and exit code are unchanged.

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
