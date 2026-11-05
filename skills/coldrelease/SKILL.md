---
name: coldrelease
description: Prepare a private Git repository for an allowlisted, history-free public release using Coldrelease, with an external human SSH signature before publication.
---

Read [the workflow guide](../../docs/coldrelease-workflow.md). Use the six
`coldrelease` workflow commands in one `.coldrelease/runs/<run-id>/` directory.

1. Run `preflight` before planning. Resolve missing license, documentation,
   dependency evidence, and verification declarations first.
2. Run `plan` with the owner's optional scanner selection. Review
   `public-export.txt`. Keep agent notes, state, scratch, private configuration,
   and maintainer release evidence out. Preserve attribution. Do not grow an
   existing allowlist silently.
3. Run `check --verify`, repair the source, and repeat in the same run. Authorize
   only reviewed verification commands. Carry byte-bound reviews in `triage.json`.
   Keep the denylist and private repository list outside publishable content.
4. Run `export --verify`. Require PASS from Coldrelease and every selected
   scanner. Retain the exact receipt and export attempt. Optional readtrial
   evidence belongs outside the export and does not replace these gates.
5. Run `approve --verify` to prepare the record. Show the receipt hash, file
   count, allowlist diff, outstanding findings, scanner selection and results,
   target repository, destination ref, and expected public head to the owner.
   Never run the signing command with a real owner's key. The owner signs outside
   the agent session and maintains an allowed-signers file the agent cannot edit
   or replace. An unsigned record grants no publication authority.
6. Run `publish --verify` only when the task explicitly authorizes publication to
   that target and ref. Supply the external trusted allowed-signers file and
   signer identity. Let the command validate the receipt, signature, scanner
   digests, and lease. Never substitute a handwritten push or weaken a failed gate.

PASS means the declared checks passed. It does not guarantee safety. No hosted
CI, model selection, deployment, or repository creation is part of this skill.
