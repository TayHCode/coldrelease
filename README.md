# Coldrelease

**Private repository in. Clean public repository out.** Point Coldrelease at a
private repository you want to open-source. It scans the files Git can see
(except generated folders such as `node_modules` and `.venv`) and every commit
for secrets, private names, emails, home paths, internal hostnames, license gaps
and missing project documents, without printing what it matched. New runs keep
their state outside the repository, and you publish a fresh export (one commit
on first publication, one added commit after), not the original or its history.

The workflow:

1. **Preflight** and **plan**: audit the source and its history, and list the
   files the public export will contain.
2. **Export**: build the one-commit copy minus exclusions, run its declared
   tests, and write a receipt tied to the checks that passed.
3. **Approve**: check the owner has not said no and record the release for the
   publication guard; it prints one guarded `git push`.
4. **Push** and **publish**: run that push, then record it; `ship` also runs the
   final gate on what was published.

[`coldrelease release`](docs/coldrelease-workflow.md#release-every-step-in-one-guided-command)
runs the steps in order and stops when one needs a decision or does not pass. Read
[Honest limitations](#honest-limitations) before you rely on a PASS.

Requires Python 3.11+ with its `venv` module, Git, and gitleaks or trufflehog:
`approve` needs a secret scanner PASS on the export. Uses only the Python
standard library.

## Quickstart

On Debian or Ubuntu, install the prerequisites as root first. Minimal images can
lack Python and Git, and stock images lack `python3-venv`, without which
`python3 -m venv` fails with `ensurepip is not available`. Then install
[gitleaks](https://github.com/gitleaks/gitleaks) on your `PATH` for the demo:

```sh
apt-get update
apt-get install -y git python3-venv
```

Then, as your normal user, install Coldrelease from a clone of this repository
into a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
coldrelease --version
coldrelease --help
```

### Try the release workflow on a demo

Stay in the clone with the virtual environment active. This creates a small demo
repository, a demo denylist kept outside it, and a local bare repository to
publish to. Nothing leaves the machine. It also names the demo denylist as this
machine's reference denylist, unless `~/.coldlocker/release-denylist.sha256` already exists.

```sh
mkdir -p ~/coldrelease-demo/.github/ISSUE_TEMPLATE ~/coldrelease-demo/tests ~/demo-private
cp LICENSE ~/coldrelease-demo/
cd ~/coldrelease-demo
printf '# Demo\n\npython -m unittest discover -s tests -q\n\n## Limitations\n\nNone known.\n' > README.md
printf 'Open a pull request.\n' > CONTRIBUTING.md
printf 'Report security issues privately.\n' > SECURITY.md
printf 'name: Bug\ndescription: Report a bug\n' > .github/ISSUE_TEMPLATE/bug.yml
printf 'import unittest\n\n\nclass DemoTest(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n' > tests/test_demo.py
printf '{"quickstart": [{"file": "README.md", "line": 3, "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}], "checks": [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}]}\n' > release-check.json
git init -q -b main
git add .
git -c user.name='Demo contributors' -c user.email=demo commit -qm 'Initial demo'
printf '["my-codename", "My Name"]\n' > ~/demo-private/terms.json
test -e ~/.coldlocker/release-denylist.sha256 || { mkdir -p ~/.coldlocker && sha256sum ~/demo-private/terms.json | cut -c1-64 > ~/.coldlocker/release-denylist.sha256; }
git init -q --bare ~/coldrelease-demo-public.git
```

Then run the workflow: preflight, plan with gitleaks, export with verification,
approve, and the guarded push and publish that `status` prints.

```sh
coldrelease preflight ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json
coldrelease plan ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json --scanner gitleaks
coldrelease export ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json --verify
coldrelease approve ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json --verify --target ~/coldrelease-demo-public.git --ref refs/heads/main
eval "$(coldrelease status ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json | sed -n 's/^next: //p')"
coldrelease publish ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json --verify --target ~/coldrelease-demo-public.git --ref refs/heads/main
git --git-dir ~/coldrelease-demo-public.git log --oneline main
```

Each `coldrelease` step prints JSON with `"outcome": "PASS"`, and the last command
shows the single fresh commit that was published. `status` printed the exact
`git push --force-with-lease` that `approve` prepared as `next`, and `publish` as
`then`, which pushes nothing and only records what the push did. Run them as two
commands: the publication guard allows the push only on its own. A local target has no
publication guard; for a GitHub target the Coldlocker guard checks that push
against the record `approve` wrote (see
[the guided release](docs/coldrelease-workflow.md#approve-and-push-through-the-publication-guard)).
Run state lives outside the source in
`$XDG_STATE_HOME/coldrelease/runs/<source>-<hash>/<run>/` (default `~/.local/state`, mode 0700).
`plan` wrote the run's `public-export.txt`; review it before `export`.
To see where a run is and the exact next command, run
`coldrelease status ~/coldrelease-demo --run demo --denylist ~/demo-private/terms.json`.
Instead of running the steps one by one, [`coldrelease release`](docs/coldrelease-workflow.md#release-every-step-in-one-guided-command)
runs every step that needs no decision and stops only for one.

### Your own repository

Print the required files, accepted README headings and manifest shape without a scan:

```sh
coldrelease --requirements
```

Then run the same steps with your repository's path, a new run name, your own
denylist and your real target URL. The denylist lists the private names, codenames
and hosts that must never be published; keep it outside the repository. Only the
owner says yes or no to a public push, with `"public_push"` in
`~/.coldlocker/guards.json`, and only the owner places the reference denylist.
[The workflow guide](docs/coldrelease-workflow.md) explains each step, external
scanners, [`status`](docs/coldrelease-workflow.md#see-where-a-run-is) and the
one-command `ship`.

When a step FAILs, stderr names each finding and its fix. If you review a finding
and it is safe to publish, such as your own name in LICENSE, add an exact approval
to `release-check.json` (see [Approving findings](#approving-findings)) and rerun.
Secrets cannot be approved.

## Single-command audit

The original flags still audit and export without a workflow run. Supply your
**external** denylist and private report destination:

```sh
coldrelease /path/to/repository --denylist /private/terms.json --reports /private/reports --scrub-plan
coldrelease /path/to/repository --denylist /private/terms.json --reports /private/reports --verify --export /private/exports/new-copy
coldrelease --validate-receipt /private/reports/.../receipt.json /private/exports/new-copy --denylist /private/terms.json --verify
```

The first command checks the repository and prints a scrub plan. The second
also runs the declared tests in a fresh virtual environment and writes a clean
export plus `receipt.json`. The third confirms the export still matches its
receipt; pass the same options you used for the export.

Test command, from the clone:

```sh
python3 -m unittest discover -s tests -q
```

Alternatively run `python3 release_check.py` directly without installing it.
`COLDRELEASE_DENYLIST` and `COLDRELEASE_REPORTS` supply the two path defaults.
The old `RELEASE_CHECK_DENYLIST` and `RELEASE_CHECK_REPORTS` still work when the new name is unset, with a one-line deprecation notice.
With no report override, reports go to `~/.local/state/coldrelease`; an existing `~/.local/state/release-check` is left in place.

The denylist is mandatory, read only at runtime and never copied to an export.
Keep it outside the repository. Formats: a JSON string array, an object containing
`terms`, an object containing `categories` with lists or `{terms: [...]}`, or one
term per line. A JSON object may also hold owner detectors for words that are
private only to you, such as internal command names:
`"patterns": [{"kind": "team-cli", "pattern": "<regex>"}]`. Each pattern matches
case-insensitively in the tree, paths and history, including across a line break,
and blocks as a personal finding of that kind. A kind must be lowercase and not a
built-in one, and a pattern must compile and match at least one character, or the run
stops with `denylist-schema`. Term indices are zero-based, in input order; category order is
JSON insertion order. Matching stays case-insensitive and literal. Purely alphabetic
terms use Unicode letters (`str.isalpha()`): a whole word or separate component
blocks, while a hit confined to one longer letter component is reviewable.
Digits, punctuation, straight/curly apostrophes, underscores, hyphens, dots, slashes
and `@` delimit components, so terms in snake_case identifiers, filenames, paths,
URLs, email addresses and hyphenated words still block when separate components.
CamelCase splits at lowercase-to-uppercase transitions and before an uppercase
letter followed by lowercase after an uppercase letter (`HTTPServer` splits into
`HTTP` and `Server`). Whole components and hits crossing these transitions block;
hits starting at an ambiguous uppercase-acronym/lowercase join also block
(`HTTPcat` might mean `HTTP` plus `cat`).
Substrings within a longer component are reviewable. Combining marks, invisible
format characters or decoding replacements beside a hit stay blocking because
their boundaries are uncertain. All-uppercase or all-lowercase
letter runs have no case transitions. Thus synthetic term `cat` blocks in `cat`,
`cat's`, `cat_file`, `cat-file`, `cat.txt`, `/cat/`, an email name `cat`, `catFood`
and `HTTPcat`, but is reviewable in `cats`, `wildcat`, `scatter` and `SCATTER`.
Terms containing any nonletter keep their existing substring rule, including the
existing ASCII-alphanumeric boundaries for alphanumeric aliases of at most three
characters. Denylist findings can be accepted only by an exact owner approval.

Reports list embedded alphabetic hits separately in `reviewable_findings`, with
`reviewable_count` and a nonblocking Markdown section. They retain safe file paths,
line numbers, term indices and fingerprints, without matched terms or surrounding
text. They do not count as blockers or as approved (`reviewed_count`) findings,
do not require scrub replacements, and cannot change the exit status on their own.
Filename redaction and venv diagnostic redaction still cover every substring.

## Verify the latest published export

For final gates on an already published export, use `--published-target` with
`--verify`. This is the supported final-gates entrypoint. Replace the paths, URL,
and full branch ref with the destination reviewed for that release:

```sh
coldrelease /path/to/published-export --denylist /private/terms.json --reports /private/reports --verify --published-target https://github.com/example/project.git refs/heads/main
```

The command queries the destination with `git ls-remote` before scanning.
Only branch refs under `refs/heads/` are accepted. Replacement refs and graft files are rejected.
The repository root must be clean, including untracked and ignored files, and its
HEAD must equal the published ref's exact commit. Index flags that hide working
file changes are rejected. The executable-bit check overrides `core.filemode=false`. A stale local tracking ref or a matching tree at a
different commit cannot satisfy the guard. The destination must hold no ref
other than the published branch and known GitHub-managed PR refs on explicit github.com HTTPS or Git SSH targets
`refs/pull/<positive-number>/head` and `refs/pull/<positive-number>/merge`.
These PR refs are explicitly accepted by policy, even at a different commit;
the gate does not scan their history. A lightweight `refs/tags/*` tag at the published commit or one of its ancestors, such as a GitHub release tag from this or an earlier release, is also accepted and listed in `published_target.tags`, unless its name holds a private term. Any other branch, tag (including an annotated tag) or ref returns FAIL with exit 1 and `published-extra-refs`,
because it can make unexported history public. An advertised `HEAD` must point at
the published branch's commit; a detached `HEAD` at any other commit, which a
plain clone would check out, returns the same FAIL. Supply the same reviewed external
`--manifest` and other audit options used for the export when needed.
Add `--expected-export EXPORT_HEAD EXPORT_TREE` with the approved receipt's
`export_head` and `export_tree` to bind the gate to that export: when the target
holds any other commit or tree, before or after the scan, it returns FAIL with exit 1
and `published-receipt-mismatch`. `ship`, `confirm-public` and the command printed by `status` always pass it.

After scanning, the command queries the destination again and rechecks HEAD, tree,
and the full inventory digest. Missing or unavailable refs, a stale target, or any
observed candidate or remote change returns INCOMPLETE with exit 2; an extra ref
that appears during the scan returns FAIL `published-extra-refs`. JSON stderr
names the blocking reason. No PASS report is written when the guard fails.

Git runs without your global and system git config, so a private HTTPS target
returns `published-ref-unavailable`. To gate it before it is made public, add
`--use-git-credentials`. Then the destination queries, and nothing else, may
ask the `credential.helper` and `credential.<url>.helper` entries from your global
git config (for example the one `gh auth setup-git` writes). No other global
setting is used. Helper values are passed through the environment, never on the
command line, and credentials never appear in output or reports. Without a
global helper, the flag returns INCOMPLETE `git-credentials-missing`.
`approve`, `publish` and `ship` take the same flag. After the guarded push, `ship`
records it and runs this gate on a fresh clone in one command; see
[the workflow guide](docs/coldrelease-workflow.md#ship-publish-and-gate-in-one-command).
Successful guard checks add `published_target` with `head`, `tree`, and `inventory`
to the report and stdout summary; the audit's findings still determine readiness.
The result describes the published ref at those checks, not future publications.
On a GitHub target, a read-only `gh api` call adds `github_settings`: the status of
secret scanning, push protection and Dependabot security updates, with a warning
for each one that isn't enabled. It never changes the outcome.

This mode does not fetch, update the checkout, or publish. If the target is stale,
prepare a clean checkout of the current published commit and rerun the guarded
command. It cannot be combined with `--export` or `--validate-receipt`.
Plain `--verify` and `--verify --export` remain candidate preparation commands;
their results do not establish that the candidate is the latest published export.

## What is checked

- Working files Git can see: tracked files plus untracked files that are not
  ignored, other than known dependency, cache and build directories. Ignored
  files (for example `.worktrees/` or `.scratch/`) are neither scanned nor
  exported. An unignored nested repository blocks as `nested-repository`. Git
  metadata is scanned separately.
- Every commit reachable from local refs and reflogs, its author/committer/message,
  every historical filename and distinct blob/path pair. Shallow history blocks.
- Denylist terms, email/phone/IP addresses, tailnet and internal hostnames, home
  paths, known-private repository references, and any owner `patterns` from the
  denylist. Also credential files, common key formats, labelled credentials and
  high-entropy strings. Media is listed for human review. JPEG/PNG EXIF (including
  GPS and UTF-16 Windows tags), PNG text chunks and PDF Info strings are decoded
  and scanned as `file!metadata`; a block that cannot be decoded is INCOMPLETE
  `metadata-unreadable`. Office properties are scanned as zip members.
- The export scan also treats commit author/committer names and emails and
  home-path usernames found in source history as private terms, so they need no
  denylist entry. Bots, `noreply@` senders, the export identity, noreply emails and
  generic home folders such as `runner` or `user` are skipped. Hits block like denylist.
- Deployment settings (`deployment-config`): Terraform `*.tfstate*` and
  `*.tfvars`, `kubeconfig` and `.kube/config`, `.npmrc`, `.pypirc` and
  `.docker/config.json` auth entries, Kubernetes `kind: Secret` with
  `data`/`stringData`, and literal values for secret-named keys in GitHub Actions
  `env:`/`with:`, Dockerfile `ENV`/`ARG` and compose `environment:` all fail.
  `${{ secrets.NAME }}` and `${VAR}` references pass. `runs-on: self-hosted`
  gives `manual-review`; approve it by exact scope, kind, path and fingerprint.
- Standard MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause or ISC root license wording,
  one licence across all root license files, and metadata consistency; dependency metadata and
  license-file evidence after installation. Dependency-free `package.json` projects
  are accepted under the restrictions below. Other root licenses and dependency
  ecosystems require manual review. NOTICE, UPSTREAM and license files are protected.
- README, limitations, CONTRIBUTING, SECURITY, issue templates (GitHub, GitLab or
  Gitea locations; see `--requirements`), tests and declared
  quickstart, test, lint and type commands. Configured Ruff/mypy checks must be listed.

Pass known-private repositories with repeated `--private-repo` flags. Each takes
`owner/name` (or `group/sub/project`) or a clone URL on any host, such as
`https://gitlab.com/group/sub/project.git` or `git@HOST:owner/name.git`.
The host is dropped, so the HTTPS, SSH and bare path forms all match.
Each one also blocks its bare repository name as a whole word, so `o/name` and a
lone `name` are caught too.
The tool never calls a hosting API to infer visibility. Supply this list separately
from the repository; public and private URLs look the same without that evidence.

## Manifest and verification

`release-check.json` declares export exclusions and commands. `--manifest PATH` can
instead use a private external manifest; a `--manifest` file that does not exist stops the run
as INCOMPLETE (exit 2), while a missing default `release-check.json` is treated as empty. `--verify` authorizes those reviewed commands
to run; without it, readiness remains blocked. No commands are inferred or executed
from arbitrary README prose. `argv` avoids shell interpretation.
With `--verify` and no manifest, no commands run. The report blocks with
`quickstart-not-declared`, `test-command-not-declared` and
`verification-not-configured`; provide a manifest with exact commands to proceed.
The release workflow's `plan` instead proposes a recipe in the run folder for you
to review and accept; see [the workflow guide](docs/coldrelease-workflow.md).

```json
{
  "exclude": ["deployment/", "local-config/"],
  "quickstart": [
    {"file": "README.md", "line": 19, "argv": ["python", "-m", "pip", "install", "."]},
    {"file": "README.md", "line": 20, "argv": ["coldrelease", "--help"]}
  ],
  "checks": [
    {"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}
  ],
  "approvals": []
}
```

Quickstart entries must match the exact command at the declared documentation line.
Verification creates a snapshot of the working files, clones that snapshot into a
fresh directory and creates a fresh venv and HOME without inherited credentials.
The first commands must install the project and any required test tools. Each
quickstart/check command's exit code and output fingerprint are recorded; its raw
output is discarded. Failed venv creation is the exception: reports include a
privacy-redacted diagnostic tail of at most 1000 characters.
`--timeout` bounds each command (default 300 seconds). A quickstart or check entry
can set its own `"timeout"` in whole seconds, for example
`{"role": "tests", "argv": [...], "timeout": 1800}`, so a slow suite declares its
budget in the manifest. The receipt binds it with the rest of the manifest. A command
that runs past its limit is killed and FAILs with `command-timeout`, naming the role,
the limit and where it came from. Pip may contact package indexes.

For non-Python commands, optionally add `"verify_tools": ["node"]` to the manifest.
The list accepts at most eight distinct bare executable names matching
`^[A-Za-z0-9._+-]+$`, excluding `.` and `..`; paths and command arguments are invalid.
Only absolute entries on the caller's PATH are searched; empty and relative entries
are ignored. Each tool and its resolved symlink target must be outside the audited
repository, original source tree, report directory and export directory. Its target
must be an absolute regular executable file. Accepted tools are symlinked into the
isolated venv bin directory before commands run. A missing, unsafe, non-executable
or conflicting tool blocks verification with `verify-tool-missing`.
The caller's PATH is not inherited; the existing system PATH suffix and isolated
HOME, XDG directories and TMPDIR remain in effect. Declare supporting tools separately
when a tool needs other executables outside the system PATH.
Verification runs in a temporary folder outside any Git repository: the first writable
one among TMPDIR, `/tmp` and `/var/tmp`. If none qualifies it stops with
`verify-workspace-in-repository`. That folder must allow running programs; on a
`noexec` temporary filesystem, set TMPDIR to another folder outside the checkout.

Every `package.json` anywhere in the audited tree, excluding `.git`, is checked
independently. A manifest avoids dependency-ecosystem manual review only when it is
a valid JSON object of at most 4 MiB with no duplicate keys, no nonempty
`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`,
`bundledDependencies`, `bundleDependencies`, `workspaces`, `overrides` or `resolutions`,
and no lifecycle script keys named `install`, `prepare`, `publish` or `dependencies`,
or starting with `pre` or `post` (including empty commands). Scripts must be an
object of string commands. Any legacy `licenses` key, truthy `gypfile` or
`binding.gyp` anywhere in the tree requires manual review. There must be no lockfile
or `node_modules` anywhere in the tree or tracked paths. Recognized lockfiles are
`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`
and `bun.lockb`. Invalid or oversized metadata and symlinked manifests remain for
manual review. A present `license` must be a string equal to the detected licence
identifier; discrepancies produce `license-metadata-mismatch`. Nested findings name
the manifest's relative path. Other ecosystem filenames keep requiring manual review.

Source distributions with dependencies can instead use exact source review.
`package-lock.json` version 3 and registry-only `bun.lock` versions 1 and 2 are
supported. Bun JSONC comments and trailing commas are accepted; duplicate keys,
nonfinite numbers and unsupported shapes remain incomplete. Every resolution,
including nested and optional platform packages, must have an exact version and
SHA-512 integrity. Bun supports a single root workspace and the default npm registry.
Local, Git, alias, patched, multi-workspace and mixed-lockfile inputs remain
incomplete. Dependency edges must resolve, except explicitly optional peers.

`bun.lockb` requires a trusted `bun` executable on the audit process's PATH.
The checker copies only the lock and manifest into a temporary directory and uses
Bun's offline, frozen, lockfile-only conversion with scripts disabled and an empty
configuration and a minimal environment. It never installs packages or runs project hooks.
Missing Bun, conversion errors, unsupported output and timeouts remain incomplete.
The original binary bytes and converted declarations both enter the evidence.

Bun locks usually omit license labels. Supply retained license documents through
`dependency_licenses` using exact npm identity keys. These entries also provide
document evidence for missing npm labels, such as `busboy` and `streamsearch`:

```json
"npm:busboy@1.6.0": {
  "version": "1.6.0",
  "integrity": "COPY THE EXACT LOCK INTEGRITY",
  "spdx": "MIT",
  "path": "licenses/busboy/1.6.0/LICENSE",
  "sha256": "COPY THE FULL SHA256 OF THE RETAINED DOCUMENT"
}
```

Each document must be a regular, readable license file inside the audited tree.
License-document paths may use `.mdx`; unknown markup and restrictive terms retain
their unknown or restrictive state and require exact source review.
Version, integrity and document digest must match. Missing Bun license labels
require this evidence; missing or stale evidence stays incomplete. The checker
uses its existing complete-text license recognition and preserves restrictive or
unknown assertions. No package-name allowlist establishes a license.

All supported source inventories still require explicit human approval of the
`npm-source-declarations-review` or `bun-source-declarations-review` finding.
The fingerprint binds the complete source tree, file modes, declarations, licenses
and policy. Any byte change invalidates the approval. Installed packages, generated
bundles and native payloads remain incomplete. The checker does not download or
authenticate license documents, prove tarball integrity or evaluate semver ranges.
Review the documents' provenance and redistribution obligations before approving.
Reports expose only paths, counts, license states and fingerprints; the existing
`npm_source_reviews` report list includes both npm and Bun source reviews.

Source-review fingerprints bind each file's executable bit, not its full mode, so a
fresh clone passes under any umask. An approval written with the older full-mode
fingerprint still passes on its original modes only. When one matches that way, the
report lists it in `fingerprint_upgrades` (`kind`, `path`, `legacy_fingerprint`,
`fingerprint`) and the CLI prints one hint line on stderr. To move it, replace that
approval's `fingerprint` in `release-check.json` with the listed `fingerprint`, keep
`scope`, `kind`, `path` and `reason`, and rerun. The checker never edits the manifest.

Approvals acknowledge a specific non-secret false positive or reviewed media file:
`scope`, `kind`, `path`, `fingerprint`. They apply to that exact scope/path/value;
they do not match every occurrence globally. Never approve unseen media. Secret
findings cannot be waived. Review approvals as code changes.
By default, approvals live in the audited repository's `release-check.json` and are
the repository author's own statement. Matched approvals stay visible as reviewed
findings in reports and contribute to `reviewed_count`. Use an external manifest
when review statements must come from outside the repository; the tool does not
authenticate the author of an approval.

### Approving findings

After a `check` or `export`, run `coldrelease review /path/to/source --run R`. It
lists each unresolved finding by scope, path, line and kind, never the value, and
asks for one decision each: `a` approve with a reason, `e` exclude the file from
the export, `f` fix it in the source, or `s` skip. Decisions go into the run's
`triage.json`; the next `check` applies them. Approvals bind to the file's current
bytes, and approve or exclude needs a source file path.

To approve by hand instead, copy the exact `scope`, `kind`, `path` and `fingerprint` from a finding. Add a
human-readable `reason` for denylist approvals. This supports verified public data,
such as a public IRS record; accepted findings stay visible in reports, and
approvals that match nothing are listed as stale. Never include the private term
in the reason.

```json
{"scope":"tree","kind":"denylist","path":"public-data.csv","fingerprint":"0123456789abcdef","reason":"Verified this exact public IRS record."}
```

Dependency licenses are recognized from SPDX expressions, metadata and classifiers.
Common permissive licenses (including generic BSD, MIT, Apache, ISC, Zlib and Python)
and weak copyleft (LGPL, MPL and EPL) are accepted. GPL and AGPL require review.
An OR expression needs an acceptable branch; AND needs every part acceptable.
An OR choice without an acceptable branch retains any GPL/AGPL or proprietary
indication. Invalid expressions retain those indications even when parsing fails.
Unknown SPDX references and exceptions also retain recognizable restrictions.
The generic `License :: OSI Approved` classifier is neutral: it neither blocks a
recognized permissive/weak-copyleft licence nor establishes a licence on its own.
Each metadata field, classifier and shipped license file is checked independently;
a separate GPL/AGPL indication wins over a permissive label or placeholder expression.
Labels must match complete known identifiers/names or a valid expression of them;
mentioning a license inside custom or proprietary wording does not establish acceptance.
A complete grant in a legacy License field is recognized as license-text evidence
before examining GPL references inside canonical LGPL/MPL text.
Unknown free-text metadata, expressions, classifiers and shipped license candidates
require review even beside accepted evidence; only empty fields and documented
placeholders (`UNKNOWN`, `NONE`, `NOASSERTION`, `Dual License`) make no assertion.
Strong-copyleft and proprietary indications still block.
Unknown licenses and unlabelled packages without recognizable license-text evidence
still require review. Recognized labels provide evidence even without a file.
Unlabelled packages need a plain license document containing recognized complete
permissive/weak-copyleft text or a valid SPDX-only declaration. Candidates include
LICENSE/LICENCE, COPYING, COPYRIGHT, UNLICENSE, license identifiers such as
`GPL-3.0.txt`, files under `licenses`/`licences`, and installed `License-File` entries.
NOTICE files are scanned for licence assertions but cannot establish acceptance or
supply digest evidence, even if declared by `License-File` or containing complete
recognizable licence text. They remain protected attribution. Shipped NOTICE
files require explicit dependency review even alongside an accepted licence label; restrictive
assertions remain blockers subject to exact dependency review approvals.
Empty, binary, source, markup and unrecognized/proprietary license files cannot
establish acceptance.
Verification reports file-based acceptance under `accepted_on_license_file`.
Shipped SPDX-only declarations use the same AND/OR rules.
Complete standard Apache, MPL and LGPL texts are recognized before examining
GPL references or ordinary words such as "commercial damages" in their terms.
Recognition checks the whole normalized text against fixed canonical fingerprints;
ordinary copyright headers, case, punctuation and whitespace may vary. Appended
restrictions or unrecognized additional license files still require review.
Copyright-prefix normalization preserves GPL/AGPL and proprietary indications.
License files use UTF-8/16/32 byte-order marks or clear NUL-byte lane patterns
for unmarked UTF-16/32. Unsupported, ambiguous or malformed encodings remain
unknown and blocking; digest evidence cannot resolve them.
A permissive SPDX header cannot hide a separate GPL grant.

Existing `dependency_licenses` entries remain supported: normalized installed package
name keys with exact `version`, `spdx` expression and full `sha256` of an installed
license file. Existing lowercase-name keys also work. This evidence clarifies ambiguous
metadata but cannot erase a detected strong-copyleft or proprietary license.
This includes indications in malformed expressions, classifiers and SPDX headers.
Only a plain license document can supply the digest; NOTICE, code and markup do
not qualify. Empty, corrupt or binary files cannot supply a resolution. Every
unknown shipped file must be covered by the supplied digest; one reviewed document
cannot waive another file's unknown obligations. Evidence that resolves an unknown license leaves a visible
`dependency-license-review` finding with `reviewed: true` and
`review_source: "dependency_licenses"`, counted in `reviewed_count`.

To accept a specific dependency finding after review, add it to the same `approvals`
array used above, with a nonempty `reason`:

```json
{
  "scope": "verification",
  "kind": "dependency-license-review",
  "path": "@dependency/example",
  "fingerprint": "0123456789abcdef",
  "reason": "Reviewed this exact distribution and accepted its obligations."
}
```

Copy the four identifying fields from the report; the example fingerprint is a
placeholder. The fingerprint binds package name, exact version, metadata and all
installed license-file hashes/paths, plus any supplied `dependency_licenses` entry.
Changed versions, files or supplied license evidence invalidate the review.
Reviewed findings remain visible with `reviewed: true` and do not count as blockers.
License obligations and source provenance still need human review.
Text recognition uses a bounded set of canonical texts; uncommon wording,
combined notices and unsupported encodings can still require explicit review.
Oversized or malformed dependency metadata blocks with a coverage finding; size,
file-count and expression-depth limits keep hostile inputs bounded. Coverage
findings cannot be waived by license evidence or approvals.
SPDX size/depth limits also apply to shipped declarations and digest evidence.
Missing file inventories, missing recorded/declared licence files, unrecorded
licence files in installed metadata, malformed headers and ambiguous package
identities also block coverage. Duplicate JSON keys and conflicting package-name
aliases cannot discard earlier gate assertions. Corrupt metadata stays a coverage
failure even beside accepted licence or review evidence.
All recognized root licence files are checked in full, including wording before
the MIT grant. Only MIT headings may be normalized away at the root; declarations
of other licences remain part of the check. Legacy `pyproject.toml` licence tables
must also agree with MIT;
neither a second root licence nor table metadata can silently bypass the check.

After venv creation fails, the tool checks whether the same interpreter can import
`ensurepip` and recognizes missing-support diagnostics across line breaks. The finding
names the Python version and the `python3.<minor>-venv` package on Debian/Ubuntu,
with general install/enable advice for other systems. Other failures keep a different
cause and a bounded error tail with private terms, credentials and absolute paths
redacted. Absolute paths, including spaces or embedded quotes, are removed through
the end of their diagnostic line; ordinary wording such as Debian/Ubuntu on other
lines remains readable.

## Export and reports

`--scrub-plan` lists exact paths to drop, findings to replace/remove by term index or
fingerprint, media to review and the requirement to flatten history. It prints no
replacement source strings. Make content fixes in a source worktree and rerun, or let
`coldrelease sanitize` apply reviewed fixes to the run's candidate copy (see
[docs/coldrelease-workflow.md](docs/coldrelease-workflow.md#sanitize-a-candidate-copy)).

`--export DIR` requires a new directory outside the source (an existing one stops
with `export-destination-exists` and a plain stderr line) and copies the current
working files, without `.git`, generated environments, credential files or manifest
exclusions. It creates exactly one commit with a generic identity, no remote and no
original history. It scans the entire export again, including its new metadata,
license/quality checks and clean-clone verification. Missing historical attribution
blocks it. Findings do not silently rewrite source, license text or file names.
A blocked export is a **private review artifact**, never a publishable success.

JSON and Markdown reports live in `<report-root>/<repo>/<UTC-timestamp>/` with
0700 directories and 0600 files. They contain counts, check statuses, safe relative
paths, line numbers, term indices, object IDs and one-way SHA-256 fingerprints (first
16 hex characters). Private filenames are replaced with path fingerprints. No
matched content, credentials or denylist terms are included. Quickstart/check
command output is represented only by fingerprints; the bounded, redacted venv
diagnostic tail is included when venv creation fails. The summary
prints only a relative report locator; without `--reports`, stderr also names the
absolute `report.json` path. Exit codes: 0 = PASS, 1 = FAIL, 2 = INCOMPLETE.
Each report has a `coverage` block, also rendered in `report.md`: every check
category with its status (`checked`, `incomplete`, `failed`, `not run`,
`not supported` or `manual review`; application security is `not run` and OCR is `not supported`; on
`export` the external scanners, and application security when bandit is selected, are `run after this report`, with outcomes in
`scanners.json`), the scanned files an export leaves out by rule (`default`,
`manifest`, `allowlist`; untracked gitignored files are never scanned or exported
and are not listed, but tracked files are scanned and exported even when they match
`.gitignore`), media still pending review, the Git refs whose history was scanned
(local refs, plus `HEAD` and `reflogs`), and a residual-risk statement. Secrets and
personal data are `incomplete` while any coverage finding is unresolved.
With an export, the exit code follows the export outcome; the original repository
can still have history findings.
A failed run prints a JSON error on stderr naming its cause: an `error` code and, for
unexpected failures, a `detail` such as `PermissionError (EACCES)` or
`CalledProcessError (git cat-file failed)` that never includes paths or file contents.
Workflow commands print the same `detail` in their JSON beside `workflow-incomplete`.
The repository path must be the top-level folder of its Git repository; a subfolder
stops with `not-repository-root`.

A workflow command can also take a remote instead of a checkout: `OWNER/REPO` (GitHub),
`https://`, `ssh://`, `file://` or `git@host:path`. `preflight` makes a fresh `--mirror`
clone of every ref into the run's state folder, records the URL and each ref's SHA in
`source.json`, and checks out the default branch beside it; later commands with the same
remote and `--run` use that clone and never fetch or push. `--use-git-credentials` lets
that clone ask your global Git credential helpers. `approve` refuses that remote or its mirror as `--target` (`target-is-source`). HTTPS URLs that carry a user, query
or fragment stop with `source-url-credentials`; a failed clone stops with
`source-clone-failed`, and a later command before `preflight` stops with `source-not-cloned`.

## Outcome and export receipt

Every audit report, including the export report, has an `outcome` (`PASS`, `FAIL`
or `INCOMPLETE`) and sorted machine-readable `reasons`. The older `ready` field is
deprecated and remains for compatibility; it is true only when the outcome is
`PASS`. PASS requires no unresolved findings, passed verification, accepted license
and verified dependency status, plus at least one accounted tree file and commit.
Unknown or missing coverage or verification evidence produces INCOMPLETE, including
verification that was not run, unavailable tools, unsupported files, pending
media review and missing license or dependency evidence. A change to the export while
it is being audited is FAIL (`candidate-mutated`). Known violations such as leaks, denylist hits,
failed commands, README commands that contradict the manifest, and missing
attribution produce FAIL. FAIL takes precedence over INCOMPLETE, while reasons for
both remain in the report. The stdout summary includes `outcome`; with `--export`
it also includes `export_outcome`. The process exit code follows that export
outcome. In particular, verification-not-run, missing verification tools and
unsupported coverage now exit 2 when no known violation makes the outcome FAIL.

When `--export` is used, `receipt.json` is written beside `report.json` in the
reports directory, never inside the export. A reports directory inside the export
is refused. The receipt binds the export inventory (every path including empty
directories, full permission bits, file bytes, symlink targets without following
links, the export's `.git` files other than the index, refs and HEAD), manifest recipe,
policy (denylist and private-repository list digests, default exclusions, verify
flag and timeout), and scanner (Coldrelease version and implementation digest,
Python version and Git version). It also records export HEAD and tree identifiers
and a `receipt_sha256`. It contains no denylist terms or private repository names.

Validate a receipt without running an audit or verification:

```sh
coldrelease --validate-receipt /private/reports/.../receipt.json /path/to/export \
  --denylist /private/terms.json --verify
```

Pass the same `--manifest`, `--private-repo` and `--timeout` options used for the
audit when applicable. An unchanged PASS receipt exits 0. Changes to export bytes,
modes, paths, refs, untracked files, recipe, policy flags or scanner produce
INCOMPLETE with reason `receipt-stale` and a `mismatched` list, and stderr gets one
line per mismatched binding saying what to repeat or redo (for `policy`, pass the same
`--denylist`, `--private-repo`, `--verify` and `--timeout`). An unparseable,
tampered, duplicate-key or unknown-schema receipt produces INCOMPLETE with reason
`receipt-invalid`. A receipt created for a FAIL or INCOMPLETE export preserves that
outcome if its bindings still match. A rejected receipt or export folder also prints
one plain stderr line saying what is wrong, without echoing any path or value.

The receipt is a hash binding, not a signature: it does not authenticate who wrote
it. Keep it outside the export and read it from the trusted job record. The workflow
requires a gitleaks or trufflehog PASS on the export, the owner's yes and the
reference denylist before `approve` records a release, and the publication guard
checks the one guarded push against that record. PASS means only that the declared checks passed on that export.

## Honest limitations

This is a release gate, not a security or legal guarantee. False positives are
expected. Entropy cannot identify every secret. The tool does not OCR images,
recognize faces, discover nonlocal Git refs or unreachable objects, or determine
hosted repository visibility. History coverage is local refs/reflogs; fetch refs
first, or pass a remote so `preflight` mirrors them. Symlinks and submodules block coverage and are never followed. Git LFS pointers
block unscanned content. Zip (docx/xlsx/jar), tar, gzip and PDF Flate text is expanded
in memory and scanned as `file.zip!member`; going over 64 MiB, 10,000 members or 4
levels is INCOMPLETE `archive-limit`. Archives and binaries still need human review. Global
Git hooks, filters and signing configuration are disabled for the audit's Git operations.

Fresh HOME/venv is isolation from credentials and caches, **not a security sandbox**.
Only verify repositories and manifest commands you trust; their code can access the
machine and network. To run them in a disposable Coldbox VM instead, add
`--verify-backend coldbox`; the receipt then records the VM image and a digest of
the VM's output. If Coldbox does not answer, verification is INCOMPLETE
`verify-backend-unavailable` unless you also pass `--allow-host-fallback`. Real browser, account, hardware and deployment checks stay
manual. This tool starts no services or timers itself.

## Development

```sh
python3 -m unittest discover -s tests -q
```

Tests use synthetic repositories and a fake external denylist in temporary folders;
they do not load user privacy files or use network services.

### Offline CLI proof

From the clone, keep temporary fixtures in the ignored scratch directory:

```sh
mkdir -p .scratch
export TMPDIR="$PWD/.scratch"
python3 -m unittest discover -s tests -p test_audit_rework.py -k _cli_ -v
```

The command should pass (exit code 0). These tests launch
`python release_check.py ... --verify` as a subprocess against generated fake
repositories. Their quickstart copies bundled fake distribution metadata into the
fresh verification venv; no package download or real dependency is needed.

`test_v3_r2_cli_permissive_weak_and_unlabelled` checks MIT, Apache, BSD, LGPL, MPL,
EPL and an unlabelled package with the bundled MIT license text. Each actual audit
must exit **0**, report `outcome: PASS` (`ready: true` for compatibility), zero blocked dependencies and no findings.
The unlabelled case must also appear in `accepted_on_license_file`.
Control cases for GPL, AGPL and an unlabelled package without license evidence
must exit **1** and report `outcome: FAIL` (`ready: false` for compatibility); those are expected blockers, so the
test command still exits 0.

The same command proves these bypasses remain blocked. Each actual audit
must exit **1** and report `outcome: FAIL` (`ready: false` for compatibility); the tests pass only when it does:

- `test_finding_1_cli_placeholder_cannot_report_ready`: NOASSERTION cannot hide GPL.
- `test_finding_2_cli_proprietary_label_blocks`: mentioning MPL in proprietary
  wording cannot establish acceptance.
- `test_finding_3_cli_empty_and_proprietary_files_block`: empty or proprietary
  license files cannot qualify an unlabelled package.
- `test_finding_4_cli_wide_gpl_and_misleading_header_block`: UTF-16 GPL text and
  a GPL grant after an MIT SPDX header still block.
- `test_final_gate_cli_parser_failures_cannot_be_digest_waived`: digest evidence
  cannot erase GPL/AGPL or proprietary indications after strict parsing fails.
- `test_final_gate_cli_missing_files_and_unbound_unknown_block`: missing inventory,
  missing/unrecorded licence files, malformed headers, duplicate identity fields
  and a second unknown document cannot be waived by another file's digest.

`test_final_gate_cli_generic_classifier_is_neutral` proves MIT, Apache, BSD and
LGPL can pass alongside the generic OSI classifier.

`test_notice_cli_cannot_accept_unlabelled_package_or_erase_restrictions` proves
NOTICE alone cannot qualify an unlabelled package, and its restrictive assertions
remain visible blockers.

It also checks standard Apache/MPL/LGPL texts, restrictive legacy fields, a second
unknown license candidate, classifier recognition, bound review evidence and
malformed metadata. Complete standard texts are bundled under `tests/fixtures/licenses`
with their original notices, so the proof does not depend on host-installed files.

### Exact source reviews for broad secret heuristics and credential URLs

Only `entropy`, `assigned-secret` and `credential-url` findings can receive a manual
false-positive review, for example a URL whose password is a placeholder. In addition to the existing exact `scope`, `kind`, `path`, and
`fingerprint` fields, the approval must have `classification: "false-positive"`,
a nonempty reason, the exact `line` and `column` occurrence, and `source_sha256` matching the entire source file. A byte
change invalidates that review. Reasons must not contain denylist terms.
Explicit token/key formats and credential-file findings remain blocking.
Do not generate reviews from counts alone: inspect the actual source context.

### Exact reviews for personal and media findings

An approval for a `personal` or `media` finding that carries a `classification` is a
false-positive review and is held to the same standard: `classification` must be
`"false-positive"`, `reason` must be nonempty and free of denylist terms, and the exact
`scope`, `kind`, `path`, `fingerprint` and `line` must match. For a finding inside a
file or commit message, `source_sha256` must also match the entire source, so any byte
change invalidates the review. A review matches one finding, never a path, category or
repository. Genuine personal data (real names, emails, phone numbers, addresses,
private paths, faces) is not a false positive and stays blocking. Approvals without
`classification` keep their existing exact-match behaviour.
