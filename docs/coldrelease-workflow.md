# Prepare and publish a reviewed source snapshot

Use `coldrelease preflight`, `plan`, `check`, `export`, `approve`, and `publish`
inside the existing Coldrelease installation. `coldrelease status` shows where a run is
and the next command. Coldrelease never pushes to a public repository itself:
`approve` records the release for the Coldlocker publication guard and prints the
one `git push` the guard allows; see
[Approve and push through the publication guard](#approve-and-push-through-the-publication-guard).
There is no second scanner or service. Python 3.11+ and Git are required. Optional
[gitleaks](https://github.com/gitleaks/gitleaks) and
[trufflehog](https://github.com/trufflesecurity/trufflehog) run as external binaries.
Nothing is vendored. Trufflehog's adapter disables credential verification and
update checks so scanning does not submit candidate credentials to providers.

PASS means the declared checks passed. It does not guarantee safety.

## Preflight cache

`preflight` caches only static license and quality checks under
`$XDG_CACHE_HOME/coldrelease/preflight-v1`, or
`~/.cache/coldrelease/preflight-v1` when `XDG_CACHE_HOME` is unset. An older
`release-check` cache folder is never read, because every key binds the checker
source, and can be deleted. Cache files
are private local reports. Keep this directory outside source repositories and
exports. A cache location inside a Git checkout disables caching.

Each key binds the actual snapshot file bytes, paths and modes, the complete
checker source and version, Python version, denylist, private repository list,
and policy including approvals. Missing, corrupt or unwritable cache entries
rerun the checks. Binary Bun lockfile conversion always reruns because it uses
an external executable. Command availability and quickstart document checks
always rerun too.

Use `coldrelease preflight SOURCE --denylist DENYLIST --no-cache` to bypass
cache reads and writes. Results are identical with and without caching.
`plan`, `check`, `export`, `approve`, `publish`, the legacy audit, and
`--published-target` never use this cache. The cache cannot approve a release.
Preflight snapshots skip the unused Git commit; exports still have one clean
commit. Shared snapshot staging sends all literal paths to one Git process.

## Survey many repositories

`coldrelease survey OWNER/* --denylist DENYLIST` lists the owner's repositories
with `gh repo list` and runs `preflight` on each. `coldrelease survey LIST
--denylist DENYLIST` reads one source per line from a file (anything `preflight`
accepts; blank lines and `#` comments are skipped). It prints one table row per
source: outcome, unresolved preflight findings counted by category (or the
INCOMPLETE reason), and missing documents. It never exports, approves or
publishes. The exit code is the worst outcome: 1 if any FAIL, else 2 if any
INCOMPLETE, else 0. An owner with 1000 or more repositories stops with INCOMPLETE
`survey-limit`; survey a list file instead. Each source gets a new run, so `--run` is refused.

## Prepare a run

The following commands are templates. Replace the paths, run ID,
repository URL, and ref with values reviewed for your release. `origin` may be
used instead of a URL. The workflow resolves its single push URL when preparing
approval and checks it again at publish. Relative local targets resolve against
the source repository. The workflow never creates a repository or changes its
visibility. Destination lookup and readback use the export's Git configuration.
Source-local URL rewrite rules do not redirect literal approved targets.

1. Keep the denylist outside the source repository. Run state is written
   outside the source, to `$XDG_STATE_HOME/coldrelease/runs/<source>-<hash>/<run>/`
   (default `~/.local/state`, every folder mode 0700); a state folder inside the
   source returns INCOMPLETE `run-state-inside-source`. A run that already exists
   under the source's old `.coldrelease/runs/<run>/` folder is still read and
   continued there, and its approvals and allowlists still serve as baselines;
   new runs never go there. Keep one run ID through repairs. Omit `--run` only when creating a new run and
   retain the generated ID printed in JSON.

   ```sh
   coldrelease preflight /path/to/source --run release-name --denylist /private/terms.json
   coldrelease plan /path/to/source --run release-name --denylist /private/terms.json
   ```

   Preflight checks the proposed tracked snapshot without executing project
   commands. It reuses the engine's license, dependency declaration, documentation,
   and verification declaration checks. Actual installed dependency licenses and
   project commands are checked during `check` and `export`. Declared project
   entrypoints may be absent before installation. An unknown ecosystem or missing
   license evidence remains blocked; preflight does not waive engine findings.
   Shallow source repositories are rejected because historical attribution
   cannot be checked beyond their available history. Fetch the complete history
   separately before starting the workflow.

   Select scanners only on `plan`, for example `--scanner gitleaks --scanner
   trufflehog --scanner osv-scanner --scanner bandit`. Omitting them records an explicit empty set.
   `approve`, `publish` and `ship` return INCOMPLETE `scanners-required` unless
   gitleaks or trufflehog PASSed on the export (osv-scanner or bandit alone does not count).
   There is no waiver.
   Install selected binaries separately: gitleaks 8.19.0 or later, trufflehog
   3.97.5 or later, osv-scanner 2.5.1 or later and bandit 1.8.0 or later (with
   `pipx install bandit`, so it runs without your user site-packages). `plan` reads each installed scanner's
   `git --help` (`scan source --help` for osv-scanner, `--help` for bandit) and returns INCOMPLETE
   `scanner-unsupported` when it lacks a flag the adapter passes; `detail` names
   the missing flags, for example `trufflehog lacks --no-ignore-tag` on
   trufflehog 3.97.4 and earlier. A missing binary makes the export INCOMPLETE.

   When the source declares no `quickstart` or `checks`, `plan` writes a
   proposed recipe to the run folder's `proposed-release-check.json`
   and never to the source. It takes install commands and `[project.scripts]`
   names from fenced lines in `README.md`. For a Python project it proposes
   `unittest discover` only when every `tests/**/test*.py` file parses, sits in
   a package folder discovery reaches, and defines a `unittest.TestCase`
   subclass with a plain `test*` method and no other tests, async tests or
   `load_tests`; otherwise it proposes `python -m pytest -q`. List `pytest` in the README install line so
   verification installs it; without pytest, or with no tests found,
   verification fails. It proposes `test`, `lint`, `typecheck` and `build` from `package.json` scripts,
   and `make test` from a `Makefile` `test:` target. Review it, edit it
   if needed, and accept it by renaming it to `release-check.json` in the same run
   folder. It may hold only `quickstart`, `checks` and `verify_tools`. `check` and
   `export` stop with `recipe-not-accepted` until you do. If `plan` stops with
   `recipe-proposal-incomplete`, add the missing quickstart or test command,
   save it as the run's `release-check.json` and rerun `plan`. The accepted
   recipe is bound to the export, and the approval records it as `recipe`.

2. Review the run folder's `public-export.txt`. It lists exact
   tracked files, without glob expansion or directories. Remove unwanted files.
   Untracked files, symlinks, credentials, agent configuration, state, scratch,
   audit/receipt evidence, and maintainer export notes are rejected. New tracked
   files do not silently enter an existing plan. Required attribution remains
   checked against every local ref and reflog, including deleted history.
   Proposed plans omit symlinks. Adding one to the allowlist is rejected. Once
   planned, preflight for `check` and `export` uses that exact reviewed allowlist,
   so unrelated tracked files cannot block it.
   If the initial preflight includes an unrelated private ecosystem, you may
   create this exact-file allowlist yourself before `plan`. Preflight and plan
   then audit only that selection. Keep required license and documentation files
   in it; omitted requirements still block the run.

   `plan` shows the diff from the previous plan. `approve` shows the diff from the
   allowlist of the most recently published run of the same source (by the
   modification time of its `published.json`); none means an empty baseline. The
   record contains the full allowlist as well as its diff.

3. Run the check and repair the source until it passes.

   ```sh
   coldrelease check /path/to/source --run release-name --denylist /private/terms.json --verify
   coldrelease export /path/to/source --run release-name --denylist /private/terms.json --verify
   ```

   `--verify` authorizes the manifest commands. Review them first. A fresh HOME and
   virtual environment do not sandbox hostile code. Each attempt has a new private
   directory under `attempts/`. Previous failed attempts remain available. Check
   audits the exact planned snapshot rather than unrelated private source history.
   Export repeats verification, creates a single generic-identity commit, and
   writes the engine's receipt. `export.json` points to that attempt. Both export
   only committed content: if any allowlisted path differs from the source `HEAD`
   (an uncommitted edit, a staged file or a mode change), they return INCOMPLETE
   `source-dirty`; commit or revert it first. The receipt records `source_head` and
   `source_tree`, and two exports of the same source commit and allowlist have the
   same `export_tree`. Checkouts whose working bytes differ from the committed
   blobs (for example CRLF conversion or `ident`) are also `source-dirty`.

   Selected scanners each receive an independent fresh clone checked out at the
   receipt's export commit. The adapter confirms its tree ID and rejects mutation.
   Gitleaks uses its default rules without repository allowlists or inline ignore
   comments. Trufflehog reports unverified findings too and requires its completion
   event and successful exit with no scan errors. Findings produce FAIL; missing
   binaries, errors, timeouts, invalid results, or absent completion produce
   INCOMPLETE. Both block approval.

   osv-scanner checks the export's lockfiles and manifests for known
   vulnerabilities. An advisory with CVSS 7.0 or higher (or a HIGH or CRITICAL
   label) and a fixed version FAILs with `scanner-findings`; other advisories are
   listed but do not block. `scanners.json` records each advisory's IDs, aliases,
   package, version, lockfile path, severity and fixed versions, and export
   prints the blocking IDs. It queries osv.dev by default. Set
   `COLDRELEASE_OSV_DB` to a directory holding `osv-scalibr/<Ecosystem>/all.zip`
   (for example from `osv-scanner scan source --offline-vulnerabilities
   --download-offline-databases`) to scan offline; a missing directory or
   ecosystem database is INCOMPLETE `scanner-database-missing`.

   bandit checks the export's Python code for insecure patterns, such as
   `subprocess` with `shell=True` or `verify=False`. Its findings are report-only
   for now: the result is PASS, `scanners.json` records each finding's rule ID,
   rule name, path, line, severity and confidence (never the matched code), and
   export prints the rule IDs. The export cannot silence it: `# nosec` comments
   and a `.bandit` file in the export are ignored. Files bandit cannot parse make
   it INCOMPLETE `scanner-error`, and the report's application security category
   is `run after this report`. Versions, executable digests, export commit/tree,
   outcomes, and output digests are retained. Every FAIL or INCOMPLETE entry in
   the attempt's `scanners.json` carries a `reason` (for example
   `scanner-missing`, `scanner-database-missing`, `scanner-timeout`, `scanner-exit-code` or
   `scanner-findings`), and export prints each INCOMPLETE reason to stderr. Raw
   scanner output stays temporary and is discarded rather than logged into run
   state.

All commands except `status` return JSON with PASS, FAIL, or INCOMPLETE and exit with 0, 1, or 2.
They do not print matching secret values, private paths, or remote command output.
Run state is private local data and must not be shared as a public report bundle.
The existing audit CLI and its `--export` option retain their previous behavior.

## Functional evidence for ColdVerify consumers

Every `check` and `export` attempt also writes `verify-evidence.json` beside its
receipt: the export's verification commands as one ColdStack run result v1
record, the shared evidence format ColdVerify writes as
`.cold/verify-evidence.json` (coldverify `docs/evidence.md`). Products that read
ColdVerify evidence can read it without knowing the receipt.

- `repo.commit` is the receipt's `export_head`, the one-commit export whose tree
  is `export_tree`. `repo.name` is the source's GitHub `owner/repo` (the remote
  source, or the checkout's `origin`). Without a GitHub name no record is
  written, because the shared schema requires one.
- `steps` are the quickstart and check commands that ran, in order. Exit 0 is
  `pass`, anything else is `fail` with `exit N` as the excerpt. A timeout (exit
  124) makes the record `incomplete`; any other failure makes it `fail`. It is
  `pass` only when verification passed, and `incomplete` when no command ran
  or a post-install check (installed project, dependency licences) blocked.
  Commands are not timed, so `duration_ms` is 0 and `time` is all `null`, as in
  ColdVerify's record.
- `artifacts` lists `receipt.json` with its SHA-256.

The record is functional evidence only. Coldrelease never reads it back:
release safety is decided by the receipt, the approval, the publication guard and the final
gate, and a `pass` record says nothing about secrets, privacy or licences.

## Remove old attempts

Every `check` and `export` keeps a full export copy under the run's `attempts/`.

```sh
coldrelease prune /path/to/source --run release-name --keep 1
```

`prune` deletes that run's oldest attempts beyond the newest `--keep` unbound
ones. It never deletes the current export attempt or the attempt whose receipt
`approval.json` or `published.json` binds, and never touches `approval.json`,
`release.git` or other runs. It takes the run lock and prints the removed and
kept attempt names.

## See where a run is

```sh
coldrelease status /path/to/source --run release-name --denylist /private/terms.json
```

`status` only reads the run's files: it creates nothing, takes no lock and
contacts no remote. It prints the run's state on the first line and the next
command on the second; `--json` prints the same as JSON. The command repeats
the `--denylist`, `--manifest`, `--private-repo`, `--timeout` and
`--use-git-credentials` options you pass to `status`, and `--target` and `--ref`
where the next step needs them. Values it cannot know are printed as `TARGET`,
`NEW_RUN` and `PUBLISHED_CLONE`; replace them. The line
contains your local paths, so do not paste it anywhere public.

| State | Next |
| --- | --- |
| `new` | `preflight` |
| `preflighted` | `plan` |
| `recipe-proposed` | review the run's `proposed-release-check.json`, then rename it to `release-check.json` |
| `planned` | `export --verify` |
| `export-not-pass` | fix the source, then `export --verify` again |
| `exported` | `approve` |
| `approval-stale` | a new run: the export changed after `approve`, and approvals are never overwritten |
| `approved` | the guarded `git push` from the run's `release.git` as `next`, and `publish` as `then`; run them as two commands, because the publication guard allows the push only on its own |
| `published <sha>` | clone the target's branch and run the final gate on it, bound to the published receipt's head and tree with `--expected-export`; INCOMPLETE `receipt-invalid` if that receipt no longer matches its digest, the approval or `published.json`. After the visibility change, run [`confirm-public`](#confirm-the-public-release) |
| `public-verified <sha>` | nothing; `confirm-public` passed on the public target for this published head. The printed `confirm-public` line checks it again |

`status` prints the guarded push only in `approved`, when the approved receipt is
the run's current export. It never prints `ship`, any other push or a visibility
change. `publish` still checks everything again.

## Carry a reviewed finding forward

`coldrelease review /path/to/source --run release-name` walks the unresolved
findings of the run's newest preflight, check or export and writes each decision
into `triage.json`: `approve` (with a reason and `file_sha256`), `exclude` (the run's
allowlist and later plans leave the path out) or `fix` (recorded only; the finding
stays until the source changes). A finding that is still unresolved is listed again
with its recorded decision, and a new answer replaces it. It never prints finding
values.

The engine's manifest `approvals` remain supported. Workflow-specific reviews go
in the run's `triage.json` list. Copy the engine finding's `scope`, `kind`, `path`,
`fingerprint`, and any required `reason`, then add `file_sha256` containing the
SHA-256 digest of the entire corresponding source file. Include separate entries
for tree and history scopes when both findings exist. Use the exact reported path;
redacted paths cannot resolve to source files and cannot receive this review.

The next plan copies the previous plan's triage. Only reviews whose file digest
still matches become engine approvals. Changing any file bytes expires the
workflow review. Engine eligibility and required reasons still apply. A review
does not erase a finding from the report.

If preflight itself reports an eligible review, create `triage.json` in that run
from its finding before `plan`. Planning, checking, and exporting apply valid
reviews before preflight. Missing licenses and other ineligible blockers still
require a source fix.

## Sanitize a candidate copy

`coldrelease sanitize /path/to/source --run release-name` applies the run's
reviewed `transforms.json` to a candidate copy in the run state and never writes
to the source. The candidate starts from the committed content of the run's
allowlist. Each entry is one of:

- `{"op": "drop", "path": "notes/draft.txt"}` leaves the file out of the candidate.
- `{"op": "replace", "path": "docs/guide.md", "fingerprint": "<16 hex>", "placeholder": "[author]"}`
  replaces every occurrence of the value behind that finding fingerprint. Copy the
  fingerprint from the check report. The value is never printed or stored.
- `{"op": "strip-metadata", "path": "photo.jpg"}` removes EXIF, XMP, IPTC and
  comment segments from a JPEG, or text, `eXIf` and `tIME` chunks from a PNG, and
  keeps the image data. Any other file stops with `transform-not-image`.
- `{"op": "env-example"}` writes `.env.example` with the keys of the source's
  root `.env` and `.env.*` files and every value blank. Only a root
  `.env.example` that holds nothing but `KEY=` lines passes the credential-file
  check.
- `{"op": "add", "template": "Apache-2.0"}` adds a built-in document that is not
  yet in the candidate: `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause` or
  `ISC` as `LICENSE`, `CONTRIBUTING` as `CONTRIBUTING.md`, `SECURITY` as
  `SECURITY.md`, or `issue-template` as `.github/ISSUE_TEMPLATE/bug_report.md`.
  `MIT`, the BSD licences and `ISC` need `"holder": "2026 Jane Doe"` for their
  copyright line; a holder that breaks the standard wording stops with
  `transform-holder`. To replace an existing `LICENSE`, `drop` it first. A licence
  is protected, so both entries need `"approve_protected": true`.

A transform that touches a licence, NOTICE, attribution or AUTHORS-style file, or
a file named in the manifest's quickstart or checks (including `--option=path`), stops with
`transform-protected` unless the entry has `"approve_protected": true`.

`sanitize` writes `changes.json`: the source commit, tree and allowlist, the
transforms digest, the candidate tree and, per change, the path, before and after
digests, fingerprint, placeholder, generated keys, and added template and holder.
After that, `preflight`, `plan`, `check` and `export` scan and export the candidate, and the receipt still
records the source commit. They stop with `candidate-stale` when the source head,
the allowlist or `transforms.json` changed (run `sanitize` again), and with
`candidate-changed` when the candidate no longer matches its recorded tree. A
change to a file that the current manifest now names in its checks stops with
`transform-protected` unless that transform was approved. Export
keeps a copy of `changes.json` in the attempt, and `approve` adds its
`changes_sha256` to the record. `publish` and `ship` refuse another
`changes.json` with `approval-changes`, and `ship` shows the change count. Once
the run is approved, `sanitize` stops with `run-approved`. A legacy run kept inside the
source stops with `run-state-inside-source`.

## Review one otherwise forbidden export path

After inspecting a public instruction file or synthetic agent example, add an
`export-path-review` to the manifest's existing `approvals` list:

```json
{
  "scope": "tree",
  "kind": "export-path-review",
  "path": "AGENTS.md",
  "source_sha256": "COPY THE FULL SHA256 OF THE REVIEWED FILE",
  "reason": "Reviewed these exact public product instructions."
}
```

The review applies to that literal repository-relative path and those exact
bytes. It does not cover a sibling with identical bytes, a directory, or a glob.
Changing the bytes expires the review. A matching review allows the file into
a proposed plan. An existing plan still requires an explicit allowlist edit.
The workflow rechecks the bytes after staging both preflight and export copies.
It also compares each reviewed export file with its committed Git blob, so line
ending normalization cannot substitute bytes that were not reviewed.

You can also place the record in `triage.json` with `file_sha256` equal to
`source_sha256`. Valid triage reviews apply before path validation and carry
forward through the existing plan mechanism.

This review changes only the forbidden-path decision. Files must still be
tracked regular files with no symlink, traversal, or manifest exclusion.
Git internals, workflow run state, and default credential exclusions remain
forbidden. Privacy, secrets, licenses, attribution, verification, receipts,
external scanners, approval and the publication guard still run unchanged. A path
review cannot waive any scanner finding or authorize publication.

## Approve and push through the publication guard

There is no signature and no key. The owner's yes or no is the
`"public_push"` switch in `~/.coldlocker/guards.json`, which only the owner can
change. Coldrelease never pushes to a public repository itself: `approve` writes
a record bound to the repository, ref, tree and receipt, and the release builder
runs one printed `git push` that the Coldlocker publication guard checks against
that record before it lets it through. `publish` then only reads the result back
and records it.

### The sequence

From an export PASS on the reference denylist to public main updated:

1. On a test host, where the reference denylist lives and
   tests may run, gate the release from the private GitHub repository, so the
   run is self-contained:

   ```sh
   coldrelease plan OWNER/REPO --run release-name --denylist ~/.config/coldrelease/denylist.json --scanner gitleaks
   coldrelease export OWNER/REPO --run release-name --denylist ~/.config/coldrelease/denylist.json --verify
   ```

   Repeat `check`, `review` and repairs as usual until export is PASS with a
   gitleaks or trufflehog PASS. Every file the public repository needs, such as
   its own `.github/workflows/*.yml` or `coldbox.toml`, must be in this gated
   export: the guard allows only the export's exact tree.
2. Move the run to the host whose publication guard will see the push (the
   [hop](#move-a-run-to-the-push-host) below).
3. On that host, approve:

   ```sh
   coldrelease approve OWNER/REPO --run release-name --denylist ~/.config/coldrelease/denylist.json --verify --target https://github.com/OWNER/PUBLIC.git --ref refs/heads/main
   ```

   The record `approve` writes on disk is the approval, even if its printed output
   is lost: `coldrelease status` shows whether the run has one (state `approved`).

4. Run the exact `git push` line that `approve` prints (also in its JSON `push`
   and `next`), on its own: the guard denies it when it is joined to another
   command with `&&` or `;`. It has this shape:

   ```sh
   git -C RUN/release.git push --force-with-lease=refs/heads/main:EXPECTED public RELEASE_SHA:refs/heads/main
   ```

5. Record it, on any host that has the run:

   ```sh
   coldrelease publish OWNER/REPO --run release-name --denylist ~/.config/coldrelease/denylist.json --verify --target https://github.com/OWNER/PUBLIC.git --ref refs/heads/main
   ```

6. Run the final gate `status` prints, and `confirm-public` once the target is
   public.

Use the same `--denylist`, external `--manifest`, `--private-repo`, `--verify`
and `--timeout` options throughout; they are bound into the receipt.

### What approve checks and writes

`approve` refuses, writing nothing, when:

- the owner says no: `"public_push": false` under `default`, or under `repos`
  for the target's GitHub `owner/repo` (which overrides `default`), returns
  INCOMPLETE `owner-public-push-no`. So does an invalid, unreadable or symlinked
  guards file, or one with a repeated key. A target that is not a GitHub `owner/repo` URL is refused when
  `default` or any `repos` entry says no. Without the file the answer is yes.
- the target names github.com but is not `https://github.com/OWNER/REPO`,
  `git@github.com:OWNER/REPO` or `ssh://git@github.com/OWNER/REPO` (with or
  without `.git`): `target-invalid`.
- the denylist is not this host's reference denylist (see
  [the reference denylist](#the-reference-denylist)).
- the receipt is older than 7 days (`receipt-expired`); the guard accepts a
  record for at most 7 days after the receipt was made, so start a new run.
- no gitleaks or trufflehog PASSed on the export (`scanners-required`).
  osv-scanner or bandit alone does not count, and there is no waiver.
- GitHub requires a status check on the target branch and applies it to admins
  (`target-requires-checks`). A direct push would be refused, so `approve`
  says so up front and names the two ways out, which only the owner can take:
  turn off "Do not allow bypassing the above settings" for that branch (the
  owner's push then lands and the checks run on it afterwards), or remove the
  required check. Then rerun `approve`.
- the run already has an approval (`approval-exists`), or the receipt, recipe,
  policy, allowlist or scanner results changed since export.

Only the target ref is read. Other branches, tags and pull refs on the target
do not matter, because the push sends one commit to one ref.

`approve` then builds the release commit in the run's own `release.git`, never
in the export checkout (the receipt covers the export's `.git`):

- On a first publication (the ref does not exist) the release commit is the
  receipt's parentless export commit, and `EXPECTED` is empty.
- When the ref exists, `EXPECTED` is its current head, and the release commit is
  the export commit with one `parent EXPECTED` line added: same tree, author,
  committer and message, and `EXPECTED` as its only parent. This is the exact
  commit the guard recomputes.

It checks the owner's switch again just before writing. It writes `approval.json` in the run with `receipt_sha256`, `source_head`,
`source_tree`, `scanners`, `target`, `ref`, `expected_public_head`,
`release_head`, `allowlist` and its diff, `recipe` and the denylist it used
(`path`, `sha256`, `terms`, `patterns`). For a GitHub target it also writes the
same record and an exact copy of the receipt to
`~/.local/state/coldlocker/release-approvals/OWNER__REPO/RELEASE_SHA/`, which is
where the guard reads them. On stderr it prints the run, target, ref, export
head, release commit, public head, the denylist's path, sha256 and term and
pattern counts, and until when the receipt is valid.

### The guarded push

The printed push is a fast-forward with a compare-and-set, never a history
rewrite. `RELEASE_SHA`'s only parent is `EXPECTED` (or it has none on a first
publication), and `--force-with-lease=REF:EXPECTED` makes Git send it only while
the public ref still holds `EXPECTED` (or does not exist). If anyone moved the
ref after `approve`, the push is refused and nothing changes; start a new run.
The publication guard allows that push only when all of these hold:

- the owner has not said no for that repository;
- a record exists for that exact repository, ref and `RELEASE_SHA`, at most 7
  days old, whose receipt is a self-consistent PASS;
- `RELEASE_SHA`'s tree is the receipt's export tree and the commit is the
  export commit itself or the export commit with only `parent EXPECTED` added;
- the lease names `EXPECTED`, and the public ref still holds it;
- the record has not been used before (each record allows one push).

When the GitHub target is PRIVATE, `approve` records `target_visibility` and
prints `git -C RUN/release.git push public RELEASE_SHA:REF` instead, because
the guard allows a private push only without a lease. Without `--force`, Git
still refuses it unless it is a fast-forward of the ref, so a moved ref is not
overwritten. If the target becomes public before the push, the guard denies
the plain push; start a new run.

Any other sha, ref, lease or remote is denied by the guard. Never add `--force`,
`--tags` or other refspecs, never edit the record and never write one by hand.

`publish` pushes nothing. It checks the record against the receipt, scanners,
allowlist and recipe again, checks the owner's switch, and reads the target ref:
when it holds `RELEASE_SHA` it writes `published.json` (`published_head`,
`parent`); when it still holds `EXPECTED` it returns INCOMPLETE
`release-not-pushed` with the push line in `detail`; any other head is FAIL
`target-moved`. A second `publish` returns INCOMPLETE `already-published`.

The final gate and `confirm-public` still read the whole public repository:
they return FAIL `published-extra-refs` when it holds refs other than the
released branch and GitHub's pull refs, because those refs are public history
the export did not check. Review or remove such refs with the owner.

When GitHub runs the public repository's own checks after the push and they
fail, the release is already public. Fix the source, gate a new run and release
again; never rewrite the public history.

### Move a run to the push host

Gates and tests run on a test host; the publication guard runs only where the
agent that pushes runs. `approve` and the push must run on that
host, because the guard reads the record from that host's home folder.
`publish` and the final gate can run on any host that has the run.

1. Gate from the private GitHub repository (`OWNER/REPO`), not a local
   checkout. Such a run is self-contained: its folder holds the source clone
   (`source/`, `mirror.git`, `source.json`), `plan.json`, `public-export.txt`,
   `triage.json` and `export.json`, and `attempts/EXPORT/` with the export
   checkout (`export/`), `receipt.json`, `manifest.json`, `allowlist.json`,
   `scanners.json` and the report.
2. Copy the whole run folder, `$XDG_STATE_HOME/coldrelease/runs/KEY/RUN/` (default
   `~/.local/state/coldrelease/runs/KEY/RUN/`), to the same relative place on the
   push host, keeping symlinks and modes (for example `rsync -a`). Copy nothing
   else.
3. Use the same Coldrelease version, Python and Git on both hosts. The receipt
   binds them; a difference returns INCOMPLETE `receipt-stale`.
4. Run `approve` there with the same options as `export`. It does not run
   `--verify` again: the flag only has to match the receipt's policy binding, and
   `approve` re-checks the receipt's self-hash and bindings, the export checkout's
   inventory and the scanner results against the copied files.

### The reference denylist

`approve` refuses a denylist that is not the host's reference denylist, so a
receipt made with a smaller or different list cannot be released:

- The owner writes the reference denylist's sha256 (64 lowercase hex characters
  and a newline) to `~/.coldlocker/release-denylist.sha256` on the push host.
  Agents cannot write there. A missing file returns INCOMPLETE
  `denylist-reference-missing`, a malformed one `denylist-reference-invalid`.
- The reference denylist file itself is placed by the owner at
  `~/.config/coldrelease/denylist.json` on the push host; agents never copy it.
  Pass that path as `--denylist`. A file with another hash returns INCOMPLETE
  `denylist-not-reference`, and the message names both hashes and the term and
  pattern counts of the file given, so a wrong file is never reported as a stale
  receipt.

### Removed

- `--identity`, `--allowed-signers`, `--key`, `ssh-keygen` signing and
  `--scanner-waiver` are gone; passing them is a usage error.
- `ship --create` and `approve --create` are refused (`create-not-supported`):
  creating and flipping a new public repository would bypass the publication
  guard.
- `publish` and `ship` never push.

To approve and publish to a private HTTPS target, pass `--use-git-credentials`
to `approve`, `publish` and the final gate. Only the target lookups may then ask
the credential helpers in your global git config; no other global setting
reaches git. Other commands return INCOMPLETE `git-credentials-selection` for the
flag, and a missing global helper returns `git-credentials-missing`. The printed
push uses your normal Git configuration.

To be reminded to list the repository on a product page, pass
`--listing-source FILE` (or set `COLDRELEASE_LISTING_SOURCE`) with a file kept
outside the published repository that names your products, such as a page's
source. After `publish` records the release it looks for the target's repository
name as a whole word in that file. If it is missing or the file cannot be read,
the PASS result gains a `reminder` field and the same text goes to stderr.

## Release: every step in one guided command

`release` runs preflight, plan, export (with verification), approve, publish and
the final gate in order, and stops where a person or the guarded push must act.
It needs `--run`, `--verify`, `--target` and `--scanner gitleaks` or
`--scanner trufflehog`; without one of these it returns INCOMPLETE with that
step's reason before it runs anything.

```sh
coldrelease release /path/to/source --run release-name --denylist /private/terms.json --verify --target https://github.com/example/project.git --ref refs/heads/main --scanner gitleaks --scanner trufflehog
```

Each step prints `release: STEP OUTCOME` on stderr. It stops at these points:

- **Findings to triage.** A preflight or export FAIL prints the findings and returns
  FAIL with `next` set to `coldrelease review SOURCE --run R`. Triage them, or fix and
  commit the source, then rerun `release`.
- **A recipe to accept.** When the source declares no quickstart or checks, `plan`
  proposes one; `release` returns INCOMPLETE `recipe-not-accepted` and prints the
  `mv` that accepts it after you read it.
- **The guarded push.** After `approve`, `publish` returns INCOMPLETE
  `release-not-pushed` with the push line in `detail`. Run it, then rerun
  `release`: it records the release and runs the final gate.

Rerunning the same command continues from the run's recorded state: a planned run
is not planned again, and a PASS export of the current source commit goes on to
approve. A run whose source moved after export is exported again. An approved run
goes straight to `publish` unless the source moved after `approve`, which returns
INCOMPLETE `source-changed` and asks for a new `--run`. A published run reruns the
final gate and reports its outcome. When an export FAILs only because an external
scanner did, `next` points at the attempt's `scanners.json` instead of `review`.

## Ship: publish and gate in one command

After the guarded push, `ship` runs `publish` and then the final gate.

```sh
coldrelease ship /path/to/source --run release-name --denylist /private/terms.json --verify --target https://github.com/example/project.git --ref refs/heads/main
```

1. `publish` runs unchanged, so `ship` refuses before the push
   (`release-not-pushed`) and for anything `publish` refuses.
2. It clones the target's branch into a temporary directory and runs the
   [guarded final gate](../README.md#verify-the-latest-published-export) on it
   with `--verify`, the same options, the export's captured manifest (so the
   run's `triage.json` reviews still apply), `--expected-export` with the
   approved receipt's head and tree, and reports under the run's `final-gate/`.
   If another writer moved the target after the readback, the gate returns FAIL
   `published-receipt-mismatch`, even when the new tree would pass on its own.
3. On a final-gate PASS it prints, and never runs, the visibility change for a
   GitHub target that is still private. After the change, run
   [`confirm-public`](#confirm-the-public-release). If the final gate does not
   pass, the result is FAIL or INCOMPLETE with `final-gate-not-pass`; fix the
   source and start a new run.

Run state is serialized with an OS lock (`flock`) on the run's `.lock` file, so
a second command on the same run returns INCOMPLETE `run-locked`. The operating
system releases the lock when its process exits, so a `.lock` file left by a
killed process or a crash does not block the next command. Run markers
(`approval.json`, `published.json` and the other JSON records) are written to a
temporary file and linked into place, so an interruption leaves either no marker
or a complete one, at most beside a dot-prefixed temporary file that `plan`
ignores. A prepared approval is never overwritten. Start a new run when an
approval needs replacement. Keep the old run for review.
Incomplete prior plans are excluded from baseline and triage selection, so an
interrupted plan does not prevent starting a new run.

Optional readtrial reports belong beside the run's evidence, outside its export.
Hosted push protection, Scorecard, and Allstar are advisory follow-ups and do not
replace this gate. No GitHub Actions, hosted CI, history rewriting or OCR is part of
this workflow. The audit expands zip, tar, gzip and PDF Flate content in memory.

## Confirm the public release

After the visibility change, check that the public target still holds exactly
the approved export:

```sh
coldrelease confirm-public /path/to/source --run release-name --denylist /private/terms.json
```

It checks the approval and the published receipt the way `status`
does, checks that `--denylist`, `--private-repo`, `--timeout` and the export's
captured manifest still match the receipt's bindings (INCOMPLETE
`receipt-stale` otherwise; pass the same options as `export`), clones the approved target and ref without credentials, and runs the
guarded final gate with `--verify` and `--expected-export` set to the approved
receipt's head and tree. Reports go under the run's `public-gate/`. On PASS it
writes `public-verified.json` (published head, export tree, receipt hash and
report name) and `status` shows `public-verified`.

- A target that moved after `ship` or `publish`, including between the final
  gate and the visibility change, returns FAIL `published-receipt-mismatch`.
  An extra ref returns FAIL `published-extra-refs`. Do not leave it public.
- A target that is still private cannot be cloned without credentials and
  returns INCOMPLETE `published-clone-failed`. `--use-git-credentials` is
  refused (`git-credentials-selection`), because the check must read the
  public URL as an anonymous reader would. Git runs with an empty temporary
  `HOME`, so a `~/.netrc` cannot log in either. A GitHub SSH target is read over
  its `https://github.com/OWNER/NAME.git` URL, because SSH keys would still work
  on a private repository. Any other SSH target, a local path or a URL with a
  user name returns INCOMPLETE `public-url-unknown`: nothing proves it is public.
- Once the run is found and locked, the command removes any earlier
  `public-verified.json` before any other check, so every later non-PASS
  leaves none. Flag errors that stop the command before it opens the run
  change nothing.
- A run that was never published returns INCOMPLETE `not-published`.

## Run final gates on the published export

Use the [guarded published-target command](../README.md#verify-the-latest-published-export)
for any final-gates claim about the latest published export. Supply a clean export
checkout, the reviewed destination URL and full branch ref, and the same denylist,
external manifest, and verification options. The guard compares the candidate
HEAD with the authoritative `git ls-remote` result before scanning and rechecks
the remote and candidate afterward. An arbitrary older export passing plain
`--verify`, or a retained receipt passing `--validate-receipt`, is not evidence
that the latest publication passed final gates.

## Reproduce the synthetic acceptance test

From a Coldrelease clone, run these exact commands. No external remote, account
or service is used.

```sh
python3 -m unittest discover -s tests -p test_release_workflow.py -k test_cli_unsafe_repaired_blocked_then_guarded_push_and_publish -v
python3 -m unittest discover -s tests -p test_release_workflow.py -v
python3 -m unittest discover -s tests -q
```

The acceptance test invokes the real `release_check.py` CLI in subprocesses. An
unsafe tracked file fails check, repaired content passes, the export passes actual
verification in a fresh virtual environment with a synthetic gitleaks, `approve`
records the release, and `publish` refuses until the printed push to a disposable
local bare repository has landed; the branch is then read back and proven to
contain exactly one commit. Other tests cover stale receipts, changed
recipes/policies, approved scanner set and digest tampering, scanner
completeness/errors/timeouts, target/ref mismatches, lease races, the owner's
switch, the reference denylist, branch protection, the 7-day limit, the host hop,
and appending to an existing branch. `tests/test_guard_record_drift.py` (kept out of
the public export with its guard copy) runs a pinned copy of the Coldlocker
publication guard against the record `approve` writes, so the two cannot drift.
Most focused safety tests replace only project verification to avoid repeating
environment setup; Git, receipt validation and local push behavior remain real.
