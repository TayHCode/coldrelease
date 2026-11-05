# Review npm source declarations

`npm-source-declarations-review` requires explicit human review of a bounded npm v3 source distribution. It never automatically accepts a dependency license. Missing, unknown, proprietary, GPL, and weak-copyleft labels remain unchanged in the evidence. Even an entirely MIT-labelled lock requires review.

The supported input is a regular `package.json` beside a regular `package-lock.json`. JSON must have unique keys, finite values, and fit the existing metadata limit. The lock must use version 3. Root dependency declarations must match the manifest. Every non-root lock entry must have a registry tarball URL, exact version, and SHA-512 integrity field. Local, Git, workspace, link, bundled, alias, and alternate lock formats remain incomplete. Root installation and publication lifecycle scripts remain incomplete. Simple registry overrides are retained and bound. Nested overrides remain unsupported.

Every lock entry participates, including optional packages for other platforms and entries outside the root dependency closure. Every declared dependency edge must resolve through the lock's ancestor package locations. An explicitly optional peer may be absent; evidence records that edge with a null target. Peer metadata without a corresponding peer declaration remains metadata and creates no invented edge. The checker does not install packages, prove tarball integrity, evaluate semver compatibility, or claim that lock metadata describes every bundled component. Those limitations are why this is a reviewed-evidence mechanism rather than automatic license coverage.

## Inspect the exact evidence

1. Run the license audit without new approvals. Retain the finding's scope, kind, path, and fingerprint.
2. Inspect the actual manifest, lock, all license labels, notices, and the intended source tree. Include optional and development entries. Resolve missing labels using actual retained evidence; do not replace them in the lock to obtain approval.
3. Review the source provenance and distribution boundary. Confirm that the tree contains no installed dependency payload or generated third-party bundle. An ordinary JavaScript file can contain a renamed bundle; automatic checks cannot establish its provenance.
4. Only after that review, add an exact approval through the existing `approvals` format. Supply a nonempty reason that records the source-only boundary and retained evidence location. Re-run the audit and check that the finding is visibly reviewed.

The Python helper `npm_source_declarations(repo, package_path, npm_source_scope(repo, manifest))` returns the complete evidence for a supported tree. Check that `npm_source_scope` returned a dictionary before calling the helper. Evidence contains raw paths and metadata. Keep it in a private report outside the audited tree. The ordinary license report exposes only sanitized manifest paths, counts, known license-state counts, and fingerprints. It does not disclose dependency labels, URLs, or file contents.

## Fingerprint and distribution boundary

The fingerprint binds the actual manifest and lock bytes through SHA-256, every lock entry, every resolved or absent optional peer edge, and the source scope. The scope binds every included file path, executable bit (git-style 644 or 755, so umask does not matter), and SHA-256 plus the audit policy. Approvals made before this change with full permission modes still match a tree with exactly those modes. Changes to whitespace, versions, integrity, overrides, optional flags, platform constraints, licenses, source files, media, or policy invalidate the approval.

Only approval records are omitted from the policy binding. The root `release-check.json` is parsed and canonicalized without its `approvals` field to avoid self-reference. Its other fields remain bound. The manifest and lock are never canonicalized before hashing their actual bytes.

The scope excludes Git internals and untracked Python/type/lint cache directories. Tracked caches and missing tracked files fail closed. It rejects symlinks, special files, installed dependency directories, build output directories, native executable and archive formats, and non-UTF-8 or NUL-containing files outside recognized media/font formats. Media and font bytes are bound, but this dependency review does not grant media or font rights. Existing attribution, license, privacy, and coverage findings remain independent blockers.

The source review is valid only for the exact bound tree. It cannot clear a populated installation, container, native dependency, or later generated bundle. An exported tree with different files needs its own review fingerprint. Known payloads cause the old unapprovable incomplete finding. A byte change to a renamed bundle invalidates an earlier approval, but a human must still recognize bundled third-party source before issuing a new approval. There is no automatic proof of source provenance.

The old `dependency-ecosystem-manual-review` finding is unchanged and remains unapprovable. Unsupported, malformed, duplicate-key, missing, and unresolved input continues to use that finding. This mechanism introduces no global coverage exception and does not approve any actual project on its own.
