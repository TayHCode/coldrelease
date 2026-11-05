# Prepare and publish a reviewed source snapshot

Use `coldrelease preflight`, `plan`, `check`, `export`, `approve`, and `publish`
inside the existing Coldrelease installation. There is no second scanner or
service. Python 3.11+, Git, and OpenSSH's `ssh-keygen -Y` are required. Optional
[gitleaks](https://github.com/gitleaks/gitleaks) and
[trufflehog](https://github.com/trufflesecurity/trufflehog) run as external binaries.
Nothing is vendored. Trufflehog's adapter disables credential verification and
update checks so scanning does not submit candidate credentials to providers.

PASS means the declared checks passed. It does not guarantee safety.

## Preflight cache

`preflight` caches only static license and quality checks under
`$XDG_CACHE_HOME/release-check/preflight-v1`, or
`~/.cache/release-check/preflight-v1` when `XDG_CACHE_HOME` is unset. Cache files
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

## Prepare a run

The following commands are templates. Replace the paths, run ID, identity,
repository URL, and ref with values reviewed for your release. `origin` may be
used instead of a URL. The workflow resolves its single push URL when preparing
approval and checks it again at publish. Relative local targets resolve against
the source repository. The workflow does not create repositories or change
visibility.
Destination lookup, push, and readback all use the export's Git configuration.
Source-local URL rewrite rules do not redirect literal signed targets.

1. Keep the denylist outside the source repository. Add `/.coldrelease/` to the
   repository's ignore rules or local `.git/info/exclude`. Do not commit run state.
   Keep one run ID through repairs. Omit `--run` only when creating a new run and
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
   trufflehog`. Omitting both records an explicit empty set. Install selected
   binaries separately. A missing binary makes the export INCOMPLETE.

2. Review `.coldrelease/runs/release-name/public-export.txt`. It lists exact
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
   most recently signed approval that verifies against the supplied external
   trust file and identity. No previous valid signature means an empty baseline.
   Signatures' local modification times determine which verified approval is most
   recent. The signed record contains the full allowlist as well as its diff.

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
   writes the engine's receipt. `export.json` points to that attempt.

   Selected scanners each receive an independent fresh clone checked out at the
   receipt's export commit. The adapter confirms its tree ID and rejects mutation.
   Gitleaks uses its default rules without repository allowlists or inline ignore
   comments. Trufflehog reports unverified findings too and requires its completion
   event and successful exit with no scan errors. Findings produce FAIL; missing
   binaries, errors, timeouts, invalid results, or absent completion produce
   INCOMPLETE. Both block approval. Versions, executable digests, export commit/tree,
   outcomes, and output digests are retained. Raw scanner output stays temporary
   and is discarded rather than logged into run state.

All commands return JSON with PASS, FAIL, or INCOMPLETE and exit with 0, 1, or 2.
They do not print matching secret values, private paths, or remote command output.
Run state is private local data and must not be shared as a public report bundle.
The existing audit CLI and its `--export` option retain their previous behavior.

## Carry a reviewed finding forward

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

## Review one otherwise forbidden export path

After inspecting a public instruction file or synthetic agent fixture, add an
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
external scanners, and signed publication approval still run unchanged. A path
review cannot waive any scanner finding or authorize publication.

## Obtain the human signature

The real signing key must remain outside the agent's reach, for example in a
hardware token or a separately controlled human session. The allowed-signers file
must be maintained outside the source, export, and run directories by a different
trusted owner. The agent must have neither write nor replacement access to it or
its directory. The CLI rejects a directly writable trust file, but cannot prove
that its owner could not change permissions or replace it through a writable
parent. A file owned by the agent's account is not a secure trust boundary.
A privileged process that can change the trust store is outside this guarantee.

An allowed-signers entry uses OpenSSH's format, for example a signer principal
followed by that person's public SSH key. Restrict its namespace to
`release-check-publish` if desired. Do not put private keys in run state.

1. Prepare the record. This command does not sign or push.

   ```sh
   coldrelease approve /path/to/source --run release-name --denylist /private/terms.json --verify --identity release-owner --allowed-signers /trusted/allowed-signers --target https://github.com/example/project.git --ref refs/heads/main
   ```

   Review `approval.json` against the actual export and its report. The summary
   includes the receipt hash, file count, allowlist diff, zero outstanding
   findings, and scanner result digests. The local record also names the target,
   fully qualified branch ref, expected public SHA or null for a missing ref,
   identity, and exact scanner set, including an explicit empty list. `approve`
   reads the target ref and validates the receipt before writing this record.

2. In the human-controlled session, sign the exact record.

   ```sh
   ssh-keygen -Y sign -f /human/signing-key -n release-check-publish /path/to/source/.coldrelease/runs/release-name/approval.json
   ```

   Return the detached `approval.json.sig` to that run. Never give an agent the
   real private key or its passphrase. Tests generate disposable synthetic keys;
   that is not the production signing procedure.

3. With publication explicitly authorized, publish the approved commit.

   ```sh
   coldrelease publish /path/to/source --run release-name --denylist /private/terms.json --verify --identity release-owner --allowed-signers /trusted/allowed-signers --target https://github.com/example/project.git --ref refs/heads/main
   ```

   Use the same denylist, external `--manifest`, `--private-repo`, `--verify`, and
   `--timeout` options throughout. Effective manifest and policy changes block
   publication. The workflow passes its captured effective manifest to the
   engine's receipt validator and requires PASS again immediately before push.
   It verifies the SSH signature and recomputes the scanner result digests using
   the signed selection, independently of the mutable plan selection.

   The workflow pushes only the receipt's exact commit SHA. It uses
   `--force-with-lease=<signed-ref>:<signed-public-SHA>` and an explicit
   `<receipt-head>:<signed-ref>` refspec. A missing ref uses an empty expected SHA.
   It never pushes the source repository's ancestry or follows tags. Any target
   URL/ref mismatch or remote ref movement blocks publication. Successful readback
   of the remote ref writes `published.json`. If a network interruption leaves the
   result uncertain, inspect the remote before creating a new approval.
   Destination lookups, push, and readback use the configured `--timeout`.
   Expiry returns INCOMPLETE and releases the run lock; a push timeout can leave
   the remote result uncertain, so inspect it before retrying.

Run state is serialized with an exclusive `.lock`. An interrupted process may
leave it behind. Confirm no workflow process still owns that run before removing
a stale lock. A prepared approval is never overwritten. Start a new run after a
signed approval needs replacement. Keep the old run for review.
Incomplete prior plans are excluded from baseline and triage selection, so an
interrupted plan does not prevent starting a new run.

Optional readtrial reports belong beside the run's evidence, outside its export.
Hosted push protection, Scorecard, and Allstar are advisory follow-ups and do not
replace this gate. No GitHub Actions, hosted CI, history rewriting, OCR, or archive
inspection is part of this workflow.

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

From a Coldrelease clone, run these exact commands. No real owner key, external
remote, account, or service is used.

```sh
python3 -m unittest discover -s tests -p test_release_workflow.py -k test_cli_unsafe_repaired_unsigned_blocked_then_signed_local_publish -v
python3 -m unittest discover -s tests -p test_release_workflow.py -v
python3 -m unittest discover -s tests -q
```

The acceptance test invokes the real `release_check.py` CLI in subprocesses. An
unsafe tracked file fails check, repaired content passes, the export passes actual
verification in a fresh virtual environment, and unsigned publication is blocked.
A disposable SSH signature then permits publication to a disposable local bare
repository, whose branch is read back and proven to contain exactly one commit.
Other tests cover stale receipts, changed recipes/policies, signed scanner set and
digest tampering, scanner completeness/errors/timeouts, target/ref mismatches,
new-ref races, and leased replacement of an existing branch. Most focused safety
tests replace only project verification to avoid repeating environment setup;
Git, receipt validation, SSH signatures, and local push behavior remain real.
