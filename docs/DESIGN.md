# QBit WORM Audit: design

Status: approved. **Owner decisions (2026-10-12): all recommendations accepted.** Every open
question in section 12 is decided as recommended.

## 1. Owner request

> "we also need to ensure that our auditing qbit supports WORM audits as well. and the phi/secure
> data qbit needs to ensure that we don't leak phi into audits"

Context: HIPAA §164.312(b) audit controls, §164.312(c)(1) integrity, §164.316(b)(2)(i) six-year
retention of required documentation (audit records are kept to the same horizon), and a
HITRUST-style review that asks three things: (1) can anyone change or delete an audit record,
(2) would we know if they did, and (3) is there a copy nobody can alter?

## 2. Goals and non-goals

Goals:
1. **Append-only at the database level.** No application path, and no ordinary database login,
   can UPDATE, DELETE or TRUNCATE audit rows. The only removal is an audited retention purge,
   after the retention date, through a separate database role.
2. **Tamper evidence.** Every audit row is linked into a hash chain. Signed checkpoints anchor the
   chain. A verification action and a daily job report the exact first broken row.
3. **Sealed copies.** New audit rows and checkpoints are exported on a schedule to an S3 bucket
   with Object Lock in COMPLIANCE mode (default six years), and can be verified against the live
   chain.
4. **No PHI in the WORM layer.** The chain and the exports seal exactly what core wrote. With
   qbit-secured-data that means HMACs for classified values, never plaintext.

Non-goals: changing what core audits (that is core's and qbit-secured-data's job); protecting
against a Postgres superuser *preventing* a change (a superuser can disable triggers; the
chain, the signatures and the Object Lock copies make that change *detectable*, see 4.5).

## 3. Scope: which tables

| Table (QQQ name / kof22 physical) | Treatment |
|---|---|
| `audit` / `audit` | Append-only (UPDATE, DELETE, TRUNCATE rejected). Chained. |
| `auditDetail` / `audit_detail` | Append-only. Chained with its header. |
| `auditTable` / `audit_table` | Lookup. DELETE and TRUNCATE rejected; UPDATE of `id` or `name` rejected (label and dates may change). Names are resolved into the chained content, so a later rename is detected. |
| `auditUser` / `audit_user` | As `audit_table`. |
| `worm_audit_chain`, `worm_audit_checkpoint`, `worm_audit_export`, `worm_audit_verification`, `worm_audit_purge` | The qbit's own tables: all append-only. |

Physical names come from the host's backend (kof22 maps camelCase to snake_case). The DDL is a
template rendered for the host's names (section 5.4).

## 4. Append-only enforcement (Postgres first)

### 4.1 Triggers
One function, `worm_audit_reject()`, attached as:
- `BEFORE UPDATE OR DELETE ... FOR EACH ROW` on every append-only table;
- `BEFORE TRUNCATE ... FOR EACH STATEMENT` on every append-only table;
- on the two lookups, a row trigger that rejects DELETE and any UPDATE that changes `id` or
  `name`.

The error is explicit and greppable:

```
ERROR:  worm_audit: audit rows are write-once; UPDATE of "audit" is not allowed (id=4211). Expired rows are removed only by worm_audit_purge().
SQLSTATE: P0001 (HINT: see qbit-worm-audit docs/DESIGN.md section 4)
```

In the application the qbit also removes the update and delete capabilities from these tables'
QQQ metadata, so the admin UI and both APIs never offer edit or delete, and a direct call gets
QQQ's standard "table does not support update/delete" error before reaching the database. The
qbit maps a `P0001` with the `worm_audit:` prefix to a `QUserFacingException`: "Audit records are
write-once and cannot be changed or deleted."

### 4.2 The retention purge (the only removal path)
`worm_audit_purge(p_cutoff timestamptz)` is a `SECURITY DEFINER` function owned by the schema
owner. `EXECUTE` is revoked from `PUBLIC` and granted only to the role `worm_audit_purger`, which
the app role is not a member of.

1. It refuses (and records a `REFUSED` row in `worm_audit_purge`, then returns; no exception, so
   the record survives) when `p_cutoff > now() - retention`. The retention interval is a constant
   compiled into the function by the changeset (default `6 years`), so shortening it is a schema
   migration, reviewed and itself audited.
2. It purges only a **chain prefix**: the audits whose chain links all lie at or before the last
   link whose audit timestamp is older than the cutoff, together with their details and links.
3. It sets a transaction-local flag (`set_config('worm_audit.purging', 'on', true)`). The reject
   trigger allows DELETE only when that flag is on **and** `current_user` is the function owner
   **and** the row is older than the retention interval. Setting the flag from another session
   does nothing, because `current_user` is not the owner.
4. It writes a `PURGED` row: who (session_user), cutoff, retention, counts, and the **anchor**
   (the last purged link's id and hash). Verification continues from the anchor.

The purge runs from an ops runbook (`psql` as `worm_audit_purger`). Version 0.1 has no UI action;
the app home lists purge rows, including refusals.

### 4.3 GRANT model

| Role | Owns | Grants on append-only tables |
|---|---|---|
| `<app>_owner` (Liquibase) | tables, functions, triggers | all (owner) |
| `<app>` (runtime) | nothing | `SELECT, INSERT`; `USAGE` on their sequences. No UPDATE, DELETE or TRUNCATE. |
| `worm_audit_purger` (ops) | nothing | `EXECUTE worm_audit_purge`; nothing else |

When a host uses one role for both migrations and runtime (kof22 today), the triggers still stop
every UPDATE, DELETE and TRUNCATE from the application, but the role can `ALTER TABLE ... DISABLE
TRIGGER`. The docs recommend splitting the roles, and the app home shows a warning when the
runtime role owns the audit tables (checked through `pg_tables.tableowner = current_user`).

### 4.4 Changesets
The qbit ships `src/main/resources/com/kingsrook/qbits/wormaudit/ddl/postgres/worm-audit.sql`,
a Liquibase formatted-SQL template with placeholders for the four core audit table names, the
app role and the retention interval, plus a renderer (`WormAuditDdl.postgres(config)`) and the
rendered default (`docs/ddl/worm-audit-postgres.sql`, snake_case names). Hosts copy the rendered
file into their changelog (kof22: `changesets/features/YYYY-MM-DD-worm-audit.sql`). It creates the
qbit tables, the functions, the triggers, the purger role (`CREATE ROLE ... NOLOGIN` when it is
missing) and the grants. It is idempotent (`CREATE OR REPLACE`, `DROP TRIGGER IF EXISTS`).

### 4.5 Threat model summary

| Actor | Can modify audit rows? | Detected by |
|---|---|---|
| App user, admin UI, QQQ APIs, assistant | No (capabilities removed; triggers) | n/a |
| SQL injection or a bug as the runtime role | No (triggers; no grant) | n/a |
| Owner role (migrations) | Only by disabling triggers | chain verification (daily), alert |
| Postgres superuser rewriting rows and recomputing the chain | Yes | checkpoint signatures (no signing key in the DB); sealed exports in Object Lock |
| Anyone deleting the sealed copies | No (COMPLIANCE mode: not even the bucket root, until expiry) | n/a |

### 4.6 Other databases (documented, not shipped in 0.1)
- **MySQL/MariaDB:** `BEFORE UPDATE`/`BEFORE DELETE` triggers with `SIGNAL SQLSTATE '45000'`;
  no TRUNCATE trigger, so revoke `DROP` from the app user; purge through a `SQL SECURITY DEFINER`
  procedure.
- **SQL Server:** `INSTEAD OF UPDATE, DELETE` triggers plus `DENY UPDATE, DELETE` to the app user.
- **H2** (tests only): no enforcement; the chain and the exports work on any QQQ RDBMS or memory
  backend, so tamper *evidence* is database-independent.

## 5. Tamper evidence

### 5.1 Canonical content (agreed with qbit-secured-data)
One canonical document per audit header: the header plus all of its detail rows, as RFC 8785 JCS
JSON (sorted keys, no insignificant whitespace, UTF-8):

```json
{"audit":{"clientChannel":null,"id":4211,"message":"Record was Edited","recordId":"17","table":"cms_page","timestamp":"2026-10-13T21:04:05.123456Z","user":"james"},
 "details":[{"fieldName":"title","id":9001,"message":"Changed Title from ...","newValue":"...","oldValue":"..."}],
 "v":1}
```

- Values are exactly as stored: no formatting, no re-masking, no lookups other than resolving
  `auditTableId`/`auditUserId` to their names. `details` are sorted by id.
- With qbit-secured-data's core hook (QRun-IO/qqq#1161, `docs/SECURED-DATA.md` §14.2), PII and
  PHI values are tokenised inside `DMLAuditAction` before `AuditAction` inserts, in the same
  transaction as the data change, so the token is the only form ever written. Stored forms (ASCII,
  at most 200 characters) in `oldValue`/`newValue` are
  `hmac:v1:<keyId>:<b64url>`, `shred:v1:<auditKeyId>:<b64url>`, `changed:v1`,
  `wiped:v1:<ruleId>` and `shredded:v1:<ruleId>` (the last is its own detail row, written when
  keys are destroyed, and is chained like any other row). Detail messages for those fields
  are replaced with value-free ones ("Changed <Label>"); header messages carry no field values.
  The canonical form, the chain and the exports therefore contain tokens only, and verifying the
  chain never needs a key. The WORM layer never reads, joins or exports
  `secured_data_audit_key` or any other `secured_data_*` table. Crypto-shredding (destroying a
  record's key) leaves the HMACs and the chain intact; they simply become unlinkable.
- The canonical JSON is never stored in the database. The chain stores ids and hashes only, so
  the qbit adds no new copy of audit content to the database.

### 5.2 The chain: a single asynchronous chainer (recommended)
`link_hash = SHA-256(prev_link_hash || 0x00 || canonical_bytes)`, hex, with the genesis
`prev_link_hash` = 64 zeros.

Core inserts audits from many threads, and headers and details may be inserted in separate
autocommit statements (core passes the caller's transaction, which may be null). Computing the
chain in core's write path would need a global lock on every audited write, and a trigger-based
chain would need the canonical form in SQL. The design instead uses **one chainer**:

- A scheduled job (every 30 s by default) takes `pg_try_advisory_xact_lock` (any other instance
  skips that tick; on non-Postgres backends, a single-row lock table with `SELECT ... FOR
  UPDATE`). It selects audit headers that are **older than a settle horizon** (default 60 s, so
  their details have been committed) and not yet chained (an anti-join on the unique
  `worm_audit_chain.audit_id`), in `(timestamp, id)` order. Then it appends links in batches.
- Link ids are assigned by the chainer as `max(id) + 1` inside the lock, not from a sequence, so
  the chain is contiguous (a sequence gaps on rollback).
- **Late arrivals** (a header whose id sorts before already-chained ones because its transaction
  committed late) are chained when they appear. The chain order is chaining order, not audit id
  order, and each link records its `audit_id`.
- **Late details** (a detail inserted after its header was chained) get their own link,
  `kind = LATE_DETAIL`, covering exactly those detail ids. Verification flags any detail not
  covered by exactly one link.
- Unique constraints back the lock: `UNIQUE (audit_id) WHERE kind = 'AUDIT'`, and the detail
  coverage.

Why not per-partition chains: they make each partition's chain shorter but multiply heads,
checkpoints and verification state, and they still need a writer per partition. One chainer
handles thousands of rows a second in batches, which is well above audit volume, and keeps a
single head to sign. The table carries no partition column (YAGNI). A future partitioned mode
would add one.

Window: a row is unchained for at most horizon plus interval (about 90 s). During that window the
triggers still protect it. The chain defends against privileged tampering, which the window does
not change materially.

### 5.3 Signed checkpoints (`worm_audit_checkpoint`)
Every hour, and every 10,000 links, the chainer writes a checkpoint for the links since the last
one: `from_link_id`, `to_link_id`, `head_hash` (the last link hash), `merkle_root` (a binary
SHA-256 Merkle tree over the range's link hashes, so a single exported range can be proven
without the whole chain), `key_id`, `public_key`, `algorithm = Ed25519` and `signature` over the
JCS form of those fields. The signing key comes from config (`WormAuditQBitConfig.signingKey`, a
supplier; kof22: env `WORM_AUDIT_SIGNING_KEY` from Infisical) and never touches the database. The
public key is stored on each checkpoint and pinned in config (`trustedPublicKeys`), so a forged
checkpoint signed with another key fails verification. Rotation adds a new key id. Old
checkpoints verify against their own pinned key.

### 5.4 Verification
**"Verify audit chain"**, a table action on `worm_audit_chain` (and on selected links), is a
standard streamed ETL:
- Extract: the links in scope (all since the purge anchor, or the selection), in id order.
- Transform: recompute each link from the live audit rows (`prev` continuity, canonical content,
  `link_hash`); check checkpoint signatures and Merkle roots; for a full run, check completeness
  (every settled audit and detail is covered exactly once).
- Load: one `worm_audit_verification` row.
- Review: "1,204,331 chain links will be verified (links 1–1,204,331, 121 checkpoints)."
- Result: "1,204,331 links verified" or, on failure, one line per break, each with the exact row:
  "Break at link 88,412 (audit 90,117, table cms_page, record 17): content differs from the
  chained hash" / "audit_detail 9,002 is not covered by the chain" / "checkpoint 41: signature
  does not verify".

**Daily verification**: a scheduled job runs the same verifier at 03:00. A failure raises
`QAlerts.raise(new AlertSignal("worm_audit.chain.break").withDedupKey("chain")...)` with the first
break in the title and the verification record as the record ref; a later pass resolves it. Every
run sends `QAlerts.heartbeat("worm_audit.verify.daily")`. `QAlerts` is the core producer SPI
(QQQ 4.1.0-RC.5), so the qbit needs no dependency on qbit-alerts. With no alerts implementation
installed the alerts go to the log.

## 6. Sealed exports

### 6.1 Export job
Daily at 02:00 (configurable), and by the table action "Export now" on `worm_audit_export`:
1. Range: links after the last export's `to_link_id`, up to the latest checkpoint. Exports are
   contiguous by construction. The app home flags a gap (a range not covered) and lag.
2. Objects under `<prefix>/<yyyy>/<mm>/<dd>/<from>-<to>/`:
   - `links.jsonl`: one line per link: `{"link":{id,kind,auditId,detailIds,prevHash,linkHash},"content":<canonical document>}`;
   - `checkpoints.jsonl`: the checkpoints in range, with signatures;
   - `manifest.json`: format version, range, counts, the SHA-256 of each file, `head_hash`,
     the previous export's manifest SHA-256 (the exports form their own chain), qbit version.
3. Each object is put through qbit-object-storage (`SystemStorage`, bucket alias from config,
   default `worm_audit`) with `LockMode.COMPLIANCE` and `retainUntil = now + retentionYears`. The
   export refuses to run, and alerts `worm_audit.export.failed`, when the bucket does not report
   the `OBJECT_LOCK` capability or the put does not echo the lock.
4. On success it inserts one `worm_audit_export` row (insert-only; a failed export leaves no row,
   and its alert carries the reason).

### 6.2 Restore and verify a sealed export
"Verify sealed export", a record action on `worm_audit_export` (standard ETL), downloads the
objects. It checks the manifest hashes, the lock mode and retain-until of each object, the link
hashes recomputed from the exported content, the checkpoint signatures, and the export's link to
the previous manifest. Then it compares each exported link and content document with the live
chain and the live audit rows. Result lines name each difference ("link 88,412: live content
differs from the sealed copy (sealed 2026-10-14)"). This is also the restore tool: the exported
content is the canonical audit content, so a verified export is evidence of the original rows
after a live tamper. A purged range stays verifiable from the sealed copy alone. Writing restored
rows back into a live table is out of scope (it would need the purge role and break append-only).

## 7. Tables

All tables use the host's RDBMS backend, are append-only (section 4), are audited by nothing
(auditing the audit tables would recurse), have full record screens, and are searchable in Quick
Search. ESB table events are on for `worm_audit_verification` and `worm_audit_export` (the
events integrations care about); chain links are high-volume and publish none.

- **`worm_audit_chain`** [Audit Chain Link]: `id` (contiguous), `kind` (AUDIT, LATE_DETAIL),
  `audit_id`, `detail_ids` (comma list, at most 250 per link), `prev_hash`, `link_hash`,
  `chained_at`. Unique `(audit_id) where kind = 'AUDIT'`.
- **`worm_audit_checkpoint`** [Checkpoint]: `id`, `from_link_id`, `to_link_id`, `link_count`,
  `head_hash`, `merkle_root`, `algorithm`, `key_id`, `public_key`, `signature`, `created_at`.
- **`worm_audit_export`** [Sealed Export]: `id`, `from_link_id`, `to_link_id`,
  `from_checkpoint_id`, `to_checkpoint_id`, `bucket_alias`, `object_prefix`, `manifest_key`,
  `manifest_sha256`, `prev_manifest_sha256`, `object_count`, `byte_count`, `lock_mode`,
  `retain_until`, `sealed_at`.
- **`worm_audit_verification`** [Verification]: `id`, `kind` (CHAIN, SEALED_EXPORT), `trigger`
  (SCHEDULE, USER), `started_at`, `finished_at`, `from_link_id`, `to_link_id`, `links_checked`,
  `outcome` (PASS, FAIL), `break_count`, `first_break_link_id`, `first_break_audit_id`,
  `first_break_reason`, `export_id`, `run_by`.
- **`worm_audit_purge`** [Purge]: `id`, `requested_at`, `requested_by`, `cutoff`,
  `retention_interval`, `outcome` (PURGED, REFUSED), `reason`, `audits_deleted`,
  `details_deleted`, `links_deleted`, `anchor_link_id`, `anchor_hash`.

Nav (the app "WORM Audit"): Home, Verifications, Sealed Exports, Checkpoints, Audit Chain, Purges.
Checkpoints list their links as a child list. Exports and verifications link their checkpoints
and links.

## 8. Permissions and the assistant wall
- Table permissions use the full name (`worm_audit_chain.read`, ...). There are no insert, edit or
  delete permissions to grant: the capabilities are absent.
- Process permissions: `worm_audit.verify`, `worm_audit.export`. The home is visible with read on
  any `worm_audit_*` table.
- The assistant channel is denied `worm_audit_*`. The qbit registers
  `ClientChannelsMetaData.ofOrWithNew(qInstance).withDeniedPattern("assistant", "worm_audit_*")`
  (core, QQQ 4.1.0-RC.6, #1141). On RC.5 it does so reflectively when the class is present. A
  one-line core PR also adds `worm_audit_*` to `ASSISTANT_DEFAULT_DENIED_PATTERNS`, so the wall
  holds even if the qbit is configured without its producer. Core's `audit*` pattern already
  covers the core audit tables.

## 9. App home
A real home that owns the data (no duplicate dashboard), built from standard widgets, served
through `/qqq/v1/widget` like every QQQ widget:
- **Chain status**: links chained, last link time, unchained backlog (with the settle horizon),
  last verification (time, outcome, links), open breaks with the first break's exact row and a
  link to the verification record.
- **Export status**: last sealed export (range, time, retain-until), lag in links and hours,
  gaps, and bucket lock state (COMPLIANCE, retention).
- **Retention**: configured years, the purge anchor, the oldest live audit, the next eligible
  purge date.
- **Recent purges**: the last 10 purge rows, refusals included.
- **Setup warnings**: triggers missing on any table (checked via `pg_trigger`), runtime role owns
  the audit tables, signing key or trusted keys missing, bucket without Object Lock.

The home must be readable at every width (390 to 1920 px) in light and dark mode, with no inner
horizontal scroll. Screenshots go in `docs/screenshots/`. If a custom endpoint is ever needed, it
registers as a `MiddlewareSpecExtension` under `/qqq/v1/qbit/worm-audit/...`
(docs/UI-API-EXTENSIONS.md). The design needs none.

## 10. Configuration (`WormAuditQBitConfig`)
`retentionYears` (6), `signingKey` (supplier of an Ed25519 private key), `trustedPublicKeys`
(key id to public key), `chainIntervalSeconds` (30), `settleHorizonSeconds` (60),
`checkpointEveryLinks` (10,000), `checkpointEveryMinutes` (60), `exportBucketAlias` (`worm_audit`),
`exportPrefix` (`worm-audit`), `exportCron` (02:00 daily), `verifyCron` (03:00 daily),
`coreAuditTableNames` (physical names, defaulting to QQQ's), `tableMetaDataCustomizer`.

## 11. Tests (acceptance)
1. **Postgres Testcontainers** (`postgres:16`): the rendered DDL applies twice (idempotent);
   UPDATE, DELETE and TRUNCATE on `audit`, `audit_detail` and each `worm_audit_*` table fail with
   the `worm_audit:` message; lookup renames fail and label changes succeed; the runtime role has
   no UPDATE/DELETE grant; `worm_audit_purge` refuses a recent cutoff (and records it), purges an
   expired prefix as the purger role, records the anchor, and verification passes from the
   anchor; setting `worm_audit.purging` from the app session does not allow DELETE.
2. **Chain**: chain, verify (PASS); a forced tamper (triggers disabled as superuser, one
   `audit_detail.new_value` changed) is detected, naming that exact link, audit and detail; a
   deleted row, an inserted row, a reordered link and a forged checkpoint are each detected.
3. **Concurrency**: 8 threads inserting audits (with late commits and details in separate
   statements) while 3 chainers run. The chain is contiguous, every audit and detail is covered
   exactly once, and verification passes.
4. **Exports (MinIO Testcontainers, bucket with Object Lock)**: export, then verify the round
   trip; every object has COMPLIANCE retention; deleting or overwriting an object version is
   refused by MinIO; a tampered live row is reported by "Verify sealed export"; a bucket without
   Object Lock makes the export refuse and alert.
5. **PHI**: a field classified PHI (`AiFieldMetaData.withClassification(DataClassification.PHI)`,
   read through `AiDataClassifications.ofField`) is written with the value `CANARY-PHI-<random>`.
   With secured-data's audit token hook (a stand-in producing the same `hmac:v1:` form in the
   qbit's tests until the core hook ships), the audit header, the details (old, new, message),
   the canonical content and the export JSONL contain neither the canary nor any substring of it
   longer than 4 characters.
6. **Alerts**: a break raises `worm_audit.chain.break` through `QAlerts` (captured by a test
   sink); a later pass resolves it.
7. Coverage gates: 70% instructions, 90% classes.

## 12. Decisions (all accepted as recommended, 2026-10-12)
| # | Question | Decision |
|---|---|---|
| 1 | Chain construction | A single asynchronous chainer with a settle horizon, contiguous link ids and late-arrival links (5.2), not synchronous or per-partition chains. |
| 2 | Chain storage | A sidecar table (`worm_audit_chain`), not columns on core tables, so core's schema is untouched and no UPDATE of audit rows is ever needed. |
| 3 | Checkpoints | Hourly or every 10,000 links; Ed25519; Merkle root per range. |
| 4 | Lookup tables | DELETE and id/name changes rejected; names resolved into the content. |
| 5 | Purge | SQL function plus a purger role only, chain-prefix only, no UI action in 0.1. |
| 6 | Export | Daily JSONL plus manifest, COMPLIANCE, six years, contiguous ranges, the exports form their own chain. |
| 7 | Databases | Postgres enforced; MySQL and SQL Server documented; evidence on any backend. |

## 13. Phases
- **(a)** DDL and renderer, capabilities guard, chain and chainer, checkpoints, verification
  action and daily job with alerts, the assistant deny pattern; tests 1–3, 5 and 6.
- **(b)** Sealed exports and the export verifier through qbit-object-storage; test 4.
- **(c)** App home and setup warnings, screenshots; kof22 adoption (draft Website-Backend PR, a
  feature changeset) and the infra proposal for an Object Lock bucket (section 14).

## 14. Adoption infrastructure (kof22, proposal only)
- **Bucket:** `kof22-worm-audit` on the kof22 MinIO, created by `minio-bucket-init` with
  `mc mb --with-lock --ignore-existing` and `mc retention set --default COMPLIANCE 6y`. Object
  Lock can only be enabled at bucket creation.
- **Policy:** `kof22-app` gets `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`,
  `s3:GetObjectRetention`, `s3:PutObjectRetention` (needed to set the lock on each put),
  `s3:GetBucketObjectLockConfiguration` on that bucket. No delete, and no
  `s3:BypassGovernanceRetention` (irrelevant under COMPLIANCE anyway).
- **Off-site:** COMPLIANCE on a single homelab MinIO stops every API deletion, but not someone
  destroying the volume. Recommend extending `media-offsite-copy` to replicate the bucket to a B2
  bucket with Object Lock (COMPLIANCE, 6 years).
- **Secrets:** `WORM_AUDIT_SIGNING_KEY` (Ed25519 PKCS#8, base64) generated in Praetor
  `terraform/infisical-config` and delivered by ESO. The public key goes in the backend config.
- **Database:** split the kof22 owner and runtime roles when convenient (4.3). Until then the
  home shows the owner warning.

These are owner-run (Praetor and cluster-gitops are applied by the owner). The qbit only
documents them.
