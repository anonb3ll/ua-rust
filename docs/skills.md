# Multi-file skill packages

The skills registry (`skill_registry`, `crates/ua-tools/src/families/skill_registry.rs`)
stores immutable, content-addressed versions of agent skills per organization,
assigned to agent labels or profiles and delivered in each node's harness config
bundle ([nodes.md](nodes.md#harness-config-bundle)).

A skill version can be either a single `SKILL.md` or a multi-file skill
directory containing `SKILL.md` plus supporting files (for example `scripts/`,
`templates/`, `references/`, `assets/`).

## Package format

Multi-file skill packages reuse the Python hub's canonical `package_manifest`
(schema version `1`) and base64 `package_payload` representation so packages
imported via `ua import python-hub` continue to verify without migration.

### Canonical manifest (`package_manifest`)

```json
{
  "files": [
    {
      "bytes": 148,
      "mode": 420,
      "path": "SKILL.md",
      "sha256": "<hex sha256>"
    },
    {
      "bytes": 22,
      "mode": 420,
      "path": "scripts/check.sh",
      "sha256": "<hex sha256>"
    }
  ],
  "schema_version": 1
}
```

- `files` is sorted strictly ascending by canonical POSIX relative `path`.
- `bytes` is the exact byte length of the raw file content.
- `sha256` is the lowercase hex SHA-256 of the raw file bytes.
- `mode` is always `420` (`0o644`) for every file published by ua-rust.
  Executable bits on disk are never honoured. On read verification, `493`
  (`0o755`) is accepted only on supporting files of packages imported from the
  Python hub (never on `SKILL.md`, and never executed or honoured).
- The canonical serialization uses `py_dumps(&manifest, None)` (compact JSON
  with sorted keys and ASCII escapes, byte-identical to Python's
  `json.dumps(manifest, sort_keys=True, separators=(",", ":"))`).

### Version hash (`content_hash`)

- **Single-file (`SKILL.md` only):** `sha256(SKILL.md bytes)` — preserves exact
  compatibility with single-file skill hashes.
- **Multi-file:** `sha256(canonical package_manifest)` — commits to every
  member's relative path, byte length, mode, and content digest. Re-publishing
  identical files returns the existing version (`idempotent: true`); changing a
  single byte or path produces a new hash and a new version.

### Stored payload (`package_payload`)

Stored in `skill_publish_staging.package_payload` (added by
`skill_registry.v3.packages`) and `skill_versions.package_payload` as a compact
JSON object mapping each relative path to the standard Base64 encoding of its
raw bytes. Raw `package_payload` is never echoed directly; read endpoints verify
every member and return structured `files` entries (`path`, `bytes`, `sha256`,
`encoding`, `content`).

## Limits

Every bound is enforced at staging time and re-verified on every read:

| Limit | Constant | Value |
| --- | --- | ---: |
| `SKILL.md` max size | `MAX_SKILL_FILE_BYTES` | 64 KiB |
| Supporting file max size | `MAX_PACKAGE_FILE_BYTES` | 512 KiB |
| Total package raw bytes | `MAX_PACKAGE_BYTES` | 2 MiB |
| Max files per package (including `SKILL.md`) | `MAX_PACKAGE_FILES` | 128 |
| Max directory entries visited | `MAX_PACKAGE_ENTRIES` | 512 |
| Max relative path length | `MAX_PACKAGE_PATH` | 240 bytes |
| Max directory depth | `MAX_PACKAGE_DEPTH` | 8 segments |
| Max supporting UTF-8 text in publish approval | `MAX_APPROVAL_TEXT_BYTES` | 256 KiB |

## Path and safety rules

- **Workspace confinement and no symlinks:** The publish target resolves inside
  the workspace without following symlinks (`symlink_metadata` on every path
  component). Inside the skill directory, every file and subdirectory is checked
  with `symlink_metadata` and opened with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`
  (re-checking `is_file()` on the open descriptor). Symlinks and special files
  (FIFOs, sockets, devices) are refused.
- **Canonical relative paths only:** Absolute paths, `..` and `.` segments,
  backslashes, colons, control characters, empty segments, and case-insensitive
  or Unicode NFC path collisions are refused.
- **No hidden files:** Any file or directory whose name starts with `.` (such as
  `.env`, `.git`, `.DS_Store`) is refused.
- **No execution:** Executable permission bits are ignored (`mode` is stored as
  `0o644`), and nothing runs at publish, staging, resolve, or install time.
- **Content screening:** `skill_review` runs on `SKILL.md` (blocking permission
  front matter and hidden text). Every supporting UTF-8 text file is also
  screened for hidden Unicode code points (blocked as `SKILL-HIDDEN-TEXT`) and
  credential/private-key material (refused before staging).

## Trust rule: staging, approval, and read verification

A skill package lands in the harness of every node assigned to it, making it a
prompt-injection path:

1. **Stage into the hub (`publish { name, path }`):** An operator (verified
   human or lifecycle operator) stages a skill directory. The hub copies every
   file into `skill_publish_staging` and creates a one-time human approval whose
   bound payload contains:
   - `content`: the full text of `SKILL.md`,
   - `package_manifest`: every member's relative path, byte size, SHA-256, and
     mode,
   - `package_files`: every supporting file, with full UTF-8 text for every text
     file (and `encoding: "binary", content: null` for binary files). If total
     supporting text exceeds `MAX_APPROVAL_TEXT_BYTES`, staging fails closed so
     no human ever approves text truncated out of the approval payload,
   - `review_findings`: findings from `skill_review`.
2. **Publish from staging (`publish { staging_id }`):** After human approval,
   the hub re-verifies the staged package bytes against its manifest and hash
   and copies them into immutable `skill_versions`. The workspace is never read
   again after staging.
3. **Verify on every read (`get`, `resolve`, `node_config`):** Every read
   recomputes the SHA-256 and byte length of every stored file, confirms
   `SKILL.md` matches the `content` column, confirms the payload contains no
   unmanifested files, and confirms the canonical manifest hashes to
   `content_hash`. Any tampering is refused (`conflict`), never served.
4. **Tenant isolation:** Versions, assignments, and staged publishes are scoped
   to `Caller.org_id`. Another organization's package or staging ID answers as
   missing (`not_found`).

## Scope

This covers slice D1 (multi-file packages pinned by content hash). The skill
catalog, team installs, and git skill sources remain out of scope (D2).
