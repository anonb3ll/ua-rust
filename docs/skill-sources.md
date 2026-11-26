# Skill git sources and catalog: trust rule

This document defines the trust boundary for importing and installing skills
from Git repositories (slice D2). No D2 implementation code is approved until
this rule is reviewed and merged. It extends the multi-file package contract in
`docs/skills.md` (sections *Package format*, *Limits*, *Path and safety rules*,
and *Trust rule: staging, approval, and read verification*) without altering D1
semantics.

A skill imported from Git lands in the harness of every node assigned to it,
making every upstream commit a prompt-injection and supply-chain boundary.

## 1. Allowed git sources (allowlist and authority)

Git skill fetching is **default-deny**. The hub never fetches, discovers, or
imports from an ad-hoc URL.

- **Allowlist shape (`skill_sources`, org-scoped):** each entry holds
  `(org_id, id, canonical_url, host, repo_path, allowed_subpaths, tracking_ref, pinned_sha, status, added_by, added_at, approval_id)`,
  where `status` is `active` or `revoked`, and `allowed_subpaths` optionally
  restricts discovery to explicit repository-relative prefixes (for example
  `skills/`).
- **URL and visibility rules (public-only in v1):**
  - **Public repositories only in v1:** fetches send no credentials and never
    fall back to the hub's GitHub token, host credential helpers, or host SSH
    agent/keys (private-source support is deferred until sources bind
    exclusively to an `org_id`-scoped managed secret with org-bound AAD and
    zero hub fallback).
  - `https://` only by default, with strict TLS certificate verification.
  - `ssh://git@host/path` (or `git@host:path`) only when explicitly enabled in
    host config for public read-only mirrors, with `BatchMode=yes`,
    `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, no agent forwarding,
    and no host keys.
  - `http://`, `git://`, `ext::`, and `file://` are refused (`file://` is
    permitted only in offline tests behind an explicit test-only flag).
  - URLs must not contain embedded credentials (`user:pass@`), query strings,
    fragments, control characters, leading `-`, or IP literals.
  - Destinations must satisfy `ua_ingress::addr` public-address classification
    (`docs/ingress.md`, *The address classifier*) on **every fetch**, not only
    at registration: loopback, RFC 1918, link-local, CGNAT, ULA, and cloud
    metadata addresses are refused, and the fetch is pinned to the classified
    IP (§3).
- **Who may manage sources:** **human operators only** (verified
  `ActorKind::Human` holding `Authority::Operator` for `caller.org_id`),
  backed by a one-time human approval bound to
  `{org_id, action, canonical_url, tracking_ref, pinned_sha, allowed_subpaths}`
  and ledgered in the same write transaction. Agents and lifecycle operators
  may list, discover, or propose imports from already-active allowlisted
  sources, but can never add or widen an allowlist entry. Revocation is
  terminal on a source row; re-allowing a previously revoked repository
  requires adding a fresh row with a new human-operator approval
  (`approval_id`) and fresh `pinned_sha`.

## 2. Dual pinning (commit SHA + D1 content hash)

Mutable Git references (branches, tags, `HEAD`, or abbreviated SHAs) are never
trusted as a skill pin. Every imported version is pinned by **both**:

1. **Exact commit SHA:** a full 40-character lowercase hex Git commit SHA
   resolved at fetch time (`<ref>^{commit}`), verified against the fetched
   object before reading any tree entry.
2. **D1 canonical content hash:** `content_hash` computed over the canonical
   `package_manifest` (`docs/skills.md`, *Package format* / *Version hash*).

Provenance is recorded on `skill_versions.source` as
`git:<canonical_url>@<40-char-sha>:<repo_relative_path>`. Calling `refresh`
resolves `tracking_ref` to a candidate SHA and reports what changed, but never
moves `pinned_sha`, never creates a version, and never updates any assignment.
`skill_assignments` continues to pin `(org_id, skill_name, pinned_version)` to
an immutable `(commit_sha, content_hash)` pair.

## 3. Fetch rules and hard bounds

The hub never checks out a Git working tree for an external skill repository.

- **Bare cache and plumbing only:** each fetch runs into a private,
  lock-serialized bare repository initialized with
  `git init --bare --template=` (empty template, mode `0700`) using
  `git fetch --quiet --depth=1 --no-tags --no-recurse-submodules --no-write-fetch-head`.
  Trees and blobs are read exclusively with plumbing (`ls-tree -r -l -z`,
  `cat-file`, `diff-tree`). No working tree is ever materialized on the hub.
- **Mandatory git hardening:** every invocation passes CLI `-c` overrides
  (which beat system, global, and repository config) and a scrubbed
  environment (stripping every `GIT_*` except explicit safe knobs, plus
  `GIT_ASKPASS`, `SSH_ASKPASS`, `SSH_AUTH_SOCK`, and proxy variables
  `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` in both upper- and
  lower-case):
  - **No hooks or fsmonitor:** `core.hooksPath=/dev/null`,
    `core.fsmonitor=false`, `protocol.ext.allow=never`,
    `GIT_TERMINAL_PROMPT=0`, `GIT_PROTOCOL_FROM_USER=0`,
    `GIT_ALLOW_PROTOCOL=https` (or `ssh` when enabled).
  - **No ambient credentials (public-only v1):** `credential.interactive=never`
    and `credential.helper=` (empty, disabling every configured helper), with
    `GIT_ASKPASS`, `SSH_ASKPASS`, and `SSH_AUTH_SOCK` unset (and for SSH,
    `IdentitiesOnly=yes` with `IdentityFile=/dev/null`).
  - **No submodules:** `submodule.recurse=false`,
    `fetch.recurseSubmodules=false`; any gitlink (`160000`) tree entry inside
    a skill directory is refused.
  - **No Git LFS or filters:** `GIT_LFS_SKIP_SMUDGE=1` and disabled
    `filter.*` drivers; LFS pointer files are never resolved over the network.
  - **DNS-rebinding, proxy, and redirect defense:**
    - Pass `-c http.proxy=` (with all proxy env vars cleared) and
      `-c http.followRedirects=false` (Git's default `initial` follows the
      first redirect across origins).
    - Resolve the remote hostname once per fetch, classify **every** returned
      IP with `ua_ingress::addr` (failing the whole fetch if any address is
      non-public), and pin the fetch to one classified IP so `git` never does
      a second unguarded lookup: pass
      `-c http.curloptResolve=<host>:<port>:<classified_ip>` for `https://`
      (or speak smart-HTTP directly through `ua_ingress::Outbound`), and for
      `ssh://` connect to `<classified_ip>` with `HostKeyAlias=<host>`.
- **Pinned-SHA fetch refusal (no full-fetch fallback):** fetching a pinned
  commit uses `--depth=1` for that exact 40-char SHA. If the server refuses a
  direct SHA want, or if `tracking_ref` resolves to a different commit than
  the requested SHA, the hub refuses and reports the error; it **never** falls
  back to an unshallow or full-history fetch that could bypass size caps.
- **Size, entry, and time caps:**
  - Per-command wall-clock timeout (120 s), bounded fetch/pack size, and
    bounded tree enumeration (`ls-tree` capped at 16 MiB and 50,000 entries;
    at most 200 discovered packages per source).
  - Every candidate package enforces all D1 limits (`docs/skills.md`,
    *Limits*): 64 KiB `SKILL.md`, 512 KiB per supporting file, 2 MiB total
    package bytes, 128 files, 512 directory entries, 240-byte path length,
    depth 8, and 256 KiB supporting approval text cap.
- **Path, symlink, and mode rules (matching D1):**
  - Symlinks (`120000`) and non-regular blob modes are refused.
  - `allowed_subpaths` entries are normalized repository-relative prefixes up to
    512 bytes; leading-dot repo directories (such as `.claude/skills`) are
    permitted as repository-level prefixes while `.`, `..`, `.git`, backslashes,
    colons, control characters, and hidden/bidi Unicode code points are refused.
  - Only canonical relative POSIX paths inside a skill directory are accepted:
    no `..`, `.`, leading `.` hidden files/directories, backslashes, colons,
    control characters, hidden/bidi Unicode code points, nested `SKILL.md`
    directories, or case-insensitive / Unicode NFC collisions (`docs/skills.md`,
    *Path and safety rules*). `source_discover` fails closed if any entry under a
    candidate package violates these path or mode rules.
  - Executable bits (`100755`) are normalized to `0o644` and never honoured.
    Nothing executes at fetch, stage, import, publish, or install time.

## 4. Re-verification at install and at every read

Once an import is approved and committed to `skill_versions`, every member byte
lives inside `package_manifest` and `package_payload`. The bare Git cache and
upstream remote are never read again to serve or install that version.

- **At stage/import:** verify the fetched commit equals the exact 40-char SHA,
  read blobs strictly by object ID, rebuild the canonical `package_manifest`
  and `content_hash`, and run all D1 screens.
- **At every read (`get`, `resolve`, `node_config`):** perform full D1
  attestation (`docs/skills.md`, *Trust rule: staging, approval, and read
  verification*) — verify every member's path, mode, decoded byte length,
  SHA-256, `SKILL.md == content`, exact manifest equality, and `content_hash`.
  `get` and `resolve` refuse tampered rows (`conflict`); `node_config` fails
  closed per skill (`skipped: "attestation_failed"`).
- **At install (catalog install and node materialization):** re-verify every
  member against `package_manifest` and `content_hash` before writing any file,
  refuse if a caller-supplied `expected_hash` disagrees, write into the target
  skill directory with `O_NOFOLLOW` and mode `0o644` (never `0o755`), refuse
  symlinks or out-of-root paths, and stage writes atomically so a failed check
  leaves no partial package on disk.

## 5. Reviewing and approving a new upstream revision

Initial imports and upstream revision upgrades both route through
`skill_publish_staging` and the full D1 safety pipeline (`docs/skills.md`,
*Path and safety rules* and *Trust rule: staging, approval, and read
verification*):

1. `skill_review` runs on `SKILL.md` (blocking permission-bearing front matter
   and hidden Unicode).
2. `String::from_utf8_lossy` screening runs on **every** non-`SKILL.md` member
   (text and allowlisted binary) for hidden Unicode (`SKILL-HIDDEN-TEXT`) and
   credential/private-key material.
3. Non-UTF-8 / NUL-containing files outside `BINARY_ASSET_EXTENSIONS` are
   refused; allowlisted binaries emit explicit `SKILL-BINARY-ASSET` findings
   carrying `path`, `bytes`, and `sha256`.
4. Total supporting text fails closed above `MAX_APPROVAL_TEXT_BYTES` (256 KiB)
   so nothing is truncated out of the human's view.

The one-time human approval payload binds
`{org_id, action, source_id, canonical_url, repo_path, previous_sha, new_sha, previous_content_hash, new_content_hash, staging_id, name}`
and displays:

- full `SKILL.md` text (plus unified diff from the previous version on upgrade),
- the full canonical `package_manifest`,
- a **member diff** listing `added`, `removed`, `modified`, and `unchanged`
  paths with old/new byte counts and SHA-256 hashes,
- full text of every supporting text file (within the 256 KiB cap), and
- all `review_findings` (including any `SKILL-BINARY-ASSET` entries).

Approving an import only creates a new immutable `skill_versions` row; pushing
that version to agents still requires an explicit, separately approved `assign`.

## 6. Revocation and yanking

- **Source revocation (`source_revoke`):** a human operator marks a
  `skill_sources` row `revoked` (ledgered in the same write transaction).
  Revocation is terminal on that row (never re-activated in place; re-allowing
  the repository requires a new row and human approval) and immediately blocks
  `refresh`, `discover`, and `import` for that source. Already-published
  `skill_versions` rows remain immutable for audit history unless yanked.
- **Version yanking (`yank`):** because `skill_versions` enforces immutability
  triggers (`BEFORE UPDATE` / `BEFORE DELETE`), yanking writes a row to a
  dedicated org-scoped table
  `skill_version_yanks(org_id, name, version, content_hash, reason, yanked_by, yanked_at)`
  behind a human-operator approval and appends a `skill.yanked` ledger event in
  the same transaction. **Yanks are permanent in v1** (no un-yank action); to
  restore a skill after fixing an issue, stage and approve a new revision with
  a distinct `content_hash`.
- **Effect of a yank:**
  - `assign` and catalog `install` refuse the yanked version.
  - `get` refuses to serve the yanked version (`conflict` / `yanked`).
  - `resolve` refuses or omits yanked versions; `node_config` fails closed per
    skill (`included: false`, `reason: "yanked"`, `skipped: "yanked"`),
    removing the skill from subsequent node bundles without disrupting other
    valid skills.
  - Re-importing or re-publishing the exact `content_hash` of a yanked version
    is refused instead of returning `idempotent: true`.

## 7. Organization fence

Every D2 table (`skill_sources`, `skill_version_yanks`, and existing
`skill_publish_staging`, `skill_versions`, `skill_assignments`) is tenant-scoped
by `org_id` with the standard `_org_exists` and `_org_immutable` triggers
(`docs/organization.md`).

- **No cross-org source sharing in v1:** each organization maintains its own
  allowlist, isolated bare cache directory
  (`$UA_DATA_HOME/skill_sources/<org_id>/<url_hash>.git`), staged imports,
  approvals, versions, and yanks.
- Another organization's `source_id`, `staging_id`, or version answers
  identically to `not_found`.
- Default-ledger events follow `ORG-EVENT-DEFAULT`: for non-default
  organizations, repository URLs, paths, skill names, commit SHAs, and content
  hashes are redacted to `null` with originator `system`.

## 8. Threat list and non-goals

### Threat list

| Threat | Mitigation |
| --- | --- |
| Upstream account takeover, force-push, or re-pointed tag | Dual pinning (`40-char SHA` + `content_hash`); `refresh` never advances pins; every revision requires member-diff human approval. |
| Malicious Git hooks, fsmonitor, submodules, or LFS smudge filters | Bare cache (`--template=`), no checkout, CLI `-c` hardening, scrubbed `GIT_*` env, plumbing-only reads, gitlinks refused. |
| Prompt injection or secrets hidden in supporting files or NUL-stuffed text | D1 `skill_review`, lossy UTF-8 scan on every member (text and binary), binary extension allowlist, explicit `SKILL-BINARY-ASSET` approval findings, 256 KiB fail-closed text cap. |
| Symlink / path-traversal escape during fetch or install | Symlinks (`120000`) refused in tree reads; canonical POSIX path + NFC/casefold collision checks; `O_NOFOLLOW` and `0o644` writes on install. |
| SSRF, DNS rebinding, or private-network probing via Git URL or redirects | Human-only allowlist, `https://` default, per-fetch `ua_ingress::addr` classification pinned via `http.curloptResolve` / `HostKeyAlias` / `ua_ingress::Outbound`, cleared proxy env + `http.proxy=`, `http.followRedirects=false`. |
| Ambient credential leakage across orgs or hosts | Public repositories only in v1; `credential.helper=`, `credential.interactive=never`, `GIT_ASKPASS`/`SSH_ASKPASS`/`SSH_AUTH_SOCK` cleared, zero hub-token fallback. |
| Oversized history fetch when server refuses SHA want | Shallow `--depth=1` fetch only; refuse and report on SHA-want refusal or `tracking_ref` mismatch, never fall back to full fetch. |
| TOCTOU between review and publish or post-publish DB tampering | Bytes copied into `skill_publish_staging` before approval, never re-read from Git cache; full member hash verification at every read and install. |
| Compromised upstream skill staying active after disclosure | `source_revoke` blocks new imports; `yank` immediately drops the version from `node_config`, `assign`, `get`, and `install`. |
| Cross-organization source, cache, or approval leakage | Strict `org_id` keying, per-org bare cache paths, org-bound approvals, `not_found` masking, and `ORG-EVENT-DEFAULT` ledger redaction. |

### Non-goals (D2 v1)

- No private Git repositories or ambient host/hub credentials (future private
  sources must bind exclusively to an `org_id`-scoped managed secret with
  org-bound AAD and zero hub fallback).
- No un-yank or in-place re-activation of revoked sources.
- No automatic background polling or auto-upgrading of pinned skills.
- No cross-org or public shared skill marketplace / source registry.
- No mandatory GPG/Sigstore commit-signature PKI (may be added later on top of
  SHA + content-hash pinning).
- No execution of install scripts, build steps, or post-install hooks.
- No transitive dependency resolution between skills.
- No agent-initiated addition of unallowlisted Git URLs.
