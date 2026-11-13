---
name: coldrelease
description: Prepare a private Git repository for an allowlisted, history-free public release using Coldrelease, with the owner's yes or no and a push the Coldlocker publication guard checks.
---

Read [the workflow guide](../../docs/coldrelease-workflow.md). Use the six
`coldrelease` workflow commands with one `--run <run-id>`. Run state lives
outside the source under `$XDG_STATE_HOME/coldrelease/runs/` (default
`~/.local/state`); `coldrelease status` prints the run's exact paths and next
command, including the guarded push line.

1. Run `preflight` before planning. Resolve missing license, documentation,
   dependency evidence, and verification declarations first.
2. Run `plan` with `--scanner gitleaks --scanner trufflehog` (plus the owner's
   other scanner selection). Review
   `public-export.txt`. Keep agent notes, state, scratch, private configuration,
   and maintainer release evidence out. Preserve attribution. Do not grow an
   existing allowlist silently.
3. Run `check --verify`, repair the source, and repeat in the same run. Authorize
   only reviewed verification commands. Carry byte-bound reviews in `triage.json`.
   Keep the denylist and private repository list outside publishable content.
4. Run `export --verify`. Require PASS from Coldrelease and every selected
   scanner. Retain the exact receipt and export attempt. Optional readtrial
   evidence belongs outside the export and does not replace these gates.
5. Run `approve --verify --target URL --ref REF` on the host whose publication
   guard will see the push, with the owner's reference denylist. It refuses
   when the owner says no (`"public_push": false`), without a gitleaks or
   trufflehog PASS, for a receipt older than 7 days, or when GitHub requires
   checks that bind admins. Show the owner what it printed: receipt, release
   commit, public head and the denylist's path, sha256 and counts. Never edit
   or hand-write an approval record.
6. Run the exact `git push --force-with-lease=REF:EXPECTED` line `approve`
   printed, only when the task authorizes publication to that target and ref.
   Never add `--force`, other refspecs or a different push. If it is refused,
   start a new run; never work around the guard.
7. Run `publish --verify` (or `ship`, which also runs the final gate) to record
   the push. Neither pushes. Never run the visibility command `ship` prints.

PASS means the declared checks passed. It does not guarantee safety. No hosted
CI, model selection, deployment, or repository creation is part of this skill.
