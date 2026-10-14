# QBit WORM Audit

Phases (a)–(c) provide PostgreSQL append-only enforcement, an asynchronous audit hash chain,
Ed25519 checkpoints, live and sealed-export verification actions, and daily jobs with core QAlerts signals.
It hashes exactly the audit values core stored; it does not read application records or
secured-data keys. Sealed JSONL exports use qbit-object-storage 0.1.0-RC.2 and configurable
Object Lock (GOVERNANCE for 30 days by default). The WORM Audit app home summarizes chain health, exports, retention and setup.

Requires Java 21, Maven wrapper 3.9.11 and QQQ 4.1.0-RC.5. PostgreSQL provides enforcement;
memory/H2 support tamper-evidence tests without database enforcement.

## Tables and permissions

All sidecar tables use the configured host backend, snake_case fields, BIGINT identifiers,
record sections, and full table-name permissions. Immutable sidecars do not audit themselves.
The editable Settings singleton uses an INTEGER ID and FIELD-level core audit. The app lists
Verifications, Sealed Exports, Checkpoints, Audit Chain, Purges, and Settings in that order.

| Table | Purpose | Permission |
|---|---|---|
| `worm_audit_verification` | Immutable USER/SCHEDULE results | `worm_audit_verification.read` |
| `worm_audit_export` | Successfully sealed export catalog | `worm_audit_export.read` |
| `worm_audit_checkpoint` | Signed ranges and Merkle roots | `worm_audit_checkpoint.read` |
| `worm_audit_chain` | Contiguous links and explicit detail coverage | `worm_audit_chain.read` |
| `worm_audit_purge` | Refusals, removal counts and retention anchors | `worm_audit_purge.read` |
| `worm_audit_settings` | Editable singleton; every edit is audited and chained | `worm_audit_settings.read`; editing needs `worm_audit_settings.edit` **and** `worm_audit.settings` |

`worm_audit.verify` authorizes the standard streamed ETL **Verify audit chain** action.
It also authorizes **Verify sealed export** on selected export records. `worm_audit.export`
authorizes **Export now** on the export table. Processes are table/record actions or schedules;
none is a navigation entry.
Insert/update/delete capabilities are absent on immutable sidecar tables; Settings allows updates only; update/delete capabilities
are removed from all four core audit tables. Internal appends use an explicit permission bypass.
Checkpoint, export and verification record screens have a bounded chain-link child list;
range endpoints and export/checkpoint references link to their records.

The table metadata customizer can configure host ESB publications. Quick Search registration
is host-owned through `QuickSearchQBitConfig.searchableTables`; add the desired tables.
Verification and export inserts use QQQ's record-change listener SPI,
so an installed ESB publisher receives those events when the host configures its destinations
on these two tables. The qbit defines no destination and configures no chain-link publication.

## Configuration

| Field | Default / contract |
|---|---|
| `backendName` | Required; core and sidecar audit tables must use this backend |
| `appName` / `appLabel` | `worm_audit` / `WORM Audit` |
| `parentAppName` | Optional host app, for example `admin` |
| `tablePathPrefix` | `/app`; standard QQQ table/record route prefix |
| `sealedStoreSupplier` | Optional host/test storage boundary; defaults to qbit-object-storage |
| `retentionYears` | 6; compiled into the migration, not changed by a runtime flag |
| `signingKey` | Optional `Supplier<SigningKey>`; `SigningKey(keyId, PrivateKey)` |
| `trustedPublicKeys` | `Map<String, PublicKey>`; must contain the signing key's public key |
| `chainIntervalSeconds` | 30 |
| `settleHorizonSeconds` | 60 (zero allowed) |
| `exportBucketAlias` | `worm_audit`; qbit-object-storage BACKUP bucket alias |
| `exportPrefix` | `worm-audit`; slash-separated letters, digits, underscores or hyphens |
| `exportCron` | `0 0 2 * * ?`; 02:00 UTC on the configured scheduler |
| `batchSize` | 1,000 headers per tick / links per insert batch |
| `lateDetailLookbackHours` | 24; positive hours, older omissions checked by full verification |
| `checkpointEveryLinks` | 10,000; maximum links in each checkpoint |
| `checkpointEveryMinutes` | 60; requires at least one uncheckpointed link |
| `verifyCron` | `0 0 3 * * ?` (03:00 UTC, Quartz syntax) |
| `schedulerName` | `worm_audit`; uses the host scheduler if present, otherwise registers Quartz |
| `coreAuditTableNames` | Overrides keyed by `audit`, `auditDetail`, `auditTable`, `auditUser` |
| `appRole` | `app` |
| `tableMetaDataCustomizer` | Optional; append-only capability guard runs afterward |

A missing signing key produces no checkpoints and adds the warning **no signing key configured**
to verification. It does not itself break the chain. Signing requires a matching public-key pin.
Rotate by adding a new pin and changing the supplier; retain old pins for old checkpoints.
Never store the private key in a database row or checked-in configuration.

## Settings

Open **WORM Audit → Settings**, record **1** (`worm_audit_settings`, labelled WORM Audit Settings).
This is a standard editable QQQ table. New records and deletion are disabled; a pre-insert
check and database constraint require ID 1. Every edit uses core FIELD-level auditing, so
the change enters the audit chain. `modify_date` and `modified_by` are stamped by the server.
Keep notes free of sensitive data; notes are audited too.

### Starter defaults and empty screens

The only seeded table is `worm_audit_settings`, by the database script (`WormAuditDdl.postgres(config)`, changeset `worm-audit:10`): `INSERT ... SELECT ... WHERE NOT EXISTS`, so it adds row 1 from the host's configured values only when absent and never overwrites an edit. There is no separate defaults changelog and no extra include line. If the row is absent the qbit runs on the configured values (`WormAuditSettings.read()` falls back), so nothing stops, but run the script to make the values visible and editable. The chain, checkpoint, export, verification and purge tables are logs written by the qbit's jobs and the database owner's purge function, and start empty.

Every table, and the app, ships help (`help/qbit-worm-audit.yaml`, the QQQ help-bundle format) saying what it is for and how its rows get created; the Next UI shows it as the empty state. A host's own help is never replaced. `WormAuditTablesGuardrailTest` and `WormAuditSettingsSeedTest` pin this.

| Field | Default | Validation / effect |
|---|---|---|
| `audit_retention_years` | 6 | 1–100; home next eligible purge date |
| `export_lock_mode` | GOVERNANCE | GOVERNANCE or COMPLIANCE; new exports |
| `export_retention_days` | 30 | 1–36500; new exports |
| `checkpoint_every_links` | 10000 | Positive integer; new checkpoint ranges |
| `checkpoint_every_minutes` | 60 | Positive integer; checkpoint cadence |
| `chain_interval_seconds` | 30 | Positive integer; **takes effect after restart** |
| `settle_horizon_seconds` | 60 | Nonnegative integer; chaining and verification |
| `late_detail_lookback_hours` | 24 | Positive integer; late-detail polling |
| `export_cron` | `0 0 2 * * ?` | Quartz cron, UTC; **takes effect after restart** |
| `verify_cron` | `0 0 3 * * ?` | Quartz cron, UTC; **takes effect after restart** |
| `notes` | Empty | Administrative notes |
| `modify_date`, `modified_by` | Server supplied | Last edit time and user |

Config values supply defaults for missing rows or null fields; a missing settings table also
falls back to config. Other database failures fail closed. `exportLockMode` and
`exportRetentionDays` are the corresponding config defaults. Runtime reads cache the row
for at most 30 seconds per application instance; local QQQ edits invalidate that cache.
Each run reads effective settings. Startup schedules read the existing row, or config when
absent. Historical checkpoints remain valid after changing their creation cadence.

Changeset `worm-audit:10` creates and seeds the table with `INSERT ... SELECT ... WHERE NOT
EXISTS`; rerunning it never overwrites an administrator change. The renderer seeds from the
host config. Memory and H2 hosts, whose settings table cannot take generic inserts, can still call
`WormAuditSettings.seed(config)` for the same insert-only behavior during single-threaded
startup (deprecated for PostgreSQL hosts, which get the row from the script).

`audit_retention_years` does **not** rewrite the database purge function. The home warns if
it differs from the compiled interval; changing that interval requires a reviewed migration.
The home also warns when export retention is shorter than audit retention and while
GOVERNANCE permits administrator bypass deletion. The runtime role receives SELECT, INSERT
and UPDATE on Settings, with no DELETE or TRUNCATE grant and no append-only triggers.

## Switching sealed exports to COMPLIANCE

Edit `export_lock_mode` to **COMPLIANCE** in Settings. New exports use COMPLIANCE once the
settings cache refreshes (within 30 seconds); existing GOVERNANCE objects keep their mode
unless an administrator explicitly extends their retention and upgrades their mode. The
verifier continues to compare each object with its export row's recorded mode and date, so
an out-of-band mode change is reported as a mismatch. The bucket default retention should
match the chosen mode and retention days, although the exporter always sends explicit values.
The settings change is audited and chained. **COMPLIANCE cannot be undone**: protected
versions cannot be deleted or have retention shortened until expiry, including by administrators.

## App home

Open `/app/worm_audit` (or `/app/admin/worm_audit` with `parentAppName="admin"`).
The full-width `wormAuditHome` HTML widget uses the standard `/qqq/v1/widget` API.
Hosts can add `wormAuditHealthCard` to their own dashboard. Both widgets and the app
require read permission on at least one WORM table, using the host's table permission rules.
The aggregate home shows only identifiers, counts, times, shortened hashes and reasons;
it never renders audit messages or field values. Record links retain the target table's permissions.

- Chain status: live link count, latest link time, settled unchained backlog and settling
  count at the configured horizon, latest verification and first open chain break.
  A subsequent full scheduled CHAIN PASS clears a reported break; a selected USER PASS does not.
- Export status: current lock mode and retention days, latest sealed range and its recorded retention, link/time lag, coverage holes
  between the purge anchor and sealed head, and bucket Object Lock capability. The unsealed
  trailing suffix is lag, not a gap. Provider failures show UNKNOWN with a value-free reason.
- Retention: configured years, purge anchor, oldest live audit and its next eligible purge date.
  The date indicates retention eligibility; the database purge function still checks the sealed prefix.
- Recent purges: the last ten requests, including refusals.
- Setup warnings: missing signing/trusted keys, unsupported or unknown Object Lock,
  daily CHAIN verification never run or older than 26 hours. PostgreSQL also checks every
  protected table's row/truncate guards, runtime ownership and the purge function.

Sections and definition-list rows wrap at narrow widths and inherit the Next UI's light/dark colors.
Empty states explicitly distinguish missing history from a passing check.

### Local demo

The test-scope server serves the API and bundled Next UI with a memory backend:

```powershell
./mvnw.cmd -o test-compile exec:java "-Dexec.classpathScope=test" "-Dexec.mainClass=com.kingsrook.qbits.wormaudit.demo.WormAuditDemoServer" "-Dexec.args=8099"
```

On macOS/Linux use `./mvnw` with the same arguments. Open <http://localhost:8099/app/worm_audit>.
No Docker or credentials are required. This anonymous demo uses synthetic `patient_note`
records audited at FIELD level through the `PhiCanaryTest` HMAC stand-in. It seeds two weeks
of actual chainer ticks, signed checkpoints, daily verifier results and immutable memory exports.
One temporary detail tamper produces a genuine FAIL before restoration and later PASSes.
The PURGED/REFUSED receipts and memory-only prefix removal are explicitly marked demo data;
PostgreSQL enforcement and real provider durability are not simulated production guarantees.

The demo includes a small unsealed suffix and unchained backlog, with no invented export gap.
The final settling count naturally ages into the backlog while the demo is open.

## Adopting in another app

Add `com.kingsrook.qbits:qbit-worm-audit:0.1.0-SNAPSHOT`. Define the host's core audit tables
with `AuditsMetaDataProvider` first, then install the qbit:

```java
WormAuditQBitConfig config = new WormAuditQBitConfig()
   .withBackendName("main")
   .withAppRole("app")
   .withSigningKey(() -> new WormAuditQBitConfig.SigningKey("2026-10", privateKey))
   .withTrustedPublicKeys(Map.of("2026-10", publicKey));
new WormAuditQBitProducer().withQBitConfig(config).produce(qInstance);
String migration = WormAuditDdl.postgres(config);
```

1. Render and review the migration, then copy it into the host Liquibase changelog.
   The [default rendering](docs/ddl/worm-audit-postgres.sql) uses `audit`, `audit_detail`,
   `audit_table`, `audit_user`, runtime role `app`, and six years. The renderer resolves table
   backend names during production; explicit overrides win. Standalone rendering uses those
   defaults. Identifiers are validated and quoted; schema-qualified core table names are supported.
2. Apply the DDL as the schema owner. It creates the five sidecar tables in `public`, functions,
   triggers, the NOLOGIN `worm_audit_purger` role, and runtime grants. Core column names must use
   the usual snake_case mappings (`audit_id`, `audit_table_id`, etc.). The migration is idempotent. Provision the purger role beforehand or give the migration role permission to create it.
3. Run as a separate runtime role with SELECT/INSERT and sequence USAGE. Do not make it a member
   of the purger role or a schema/table owner. Use the host's PostgreSQL RDBMS strategy (RC.5's
   base strategy uses MySQL quoting; see the test host strategy in `RdbmsTestSupport`).
4. Start QQQ's standard scheduler with its system session and grant users only the required read
   and verification permissions. Point the existing alerts implementation at core `QAlerts`.
5. Configure ESB publications on verification/export in the table customizer. Register all five
   tables in the host Quick Search config with `SearchableTableConfig` / `SearchableFieldConfig`.
   Index identifiers and status fields; set basepull timestamps to `chained_at`, `created_at`,
   `sealed_at`, `finished_at`, and `requested_at` respectively (these tables have no `modifyDate`).

The RC.6 assistant deny API is registered reflectively when present; absence in RC.5 is a no-op.
The qbit declares `wormaudit.chain.break` (CRITICAL), `wormaudit.export.failed` (ERROR),
and the daily verification/export heartbeat types through core alert-type metadata.
Daily heartbeat monitors expect a 24-hour interval with 2 hours of grace (overdue at 26 hours).
`QAlerts` dispatches to the installed sink or its logging fallback. Every scheduled verification sends
`wormaudit.verify.daily`; FAIL raises with the first break and verification record reference;
PASS resolves dedup key `chain`.

## Chain and verification format

- JCS v1 uses UTF-16 key ordering, strict surrogate validation and UTC microsecond timestamps.
  IDs are integer longs except canonical `recordId`, which is a string. No floating-point values.
- Link hashes concatenate the predecessor's **64 lowercase ASCII hex bytes**, one NUL byte,
  and canonical UTF-8 bytes. Genesis is 64 ASCII zeroes.
- Every link names the detail IDs it covered, at most 250. A PostgreSQL insert guard and GIN
  overlap index reject duplicate coverage under the same advisory lock. Overflow and later details use
  `LATE_DETAIL` links with the same canonical header-and-detail-subset document. The canonical
  JSON is never persisted. A v1 content mismatch can identify the link, audit and covered detail
  IDs, but cannot identify one changed field among multiple details without original content.
- PostgreSQL chaining uses transaction-scoped advisory lock `86753090421` shared with purge.
  Other backends use a JVM-wide lock and require one writer JVM. SQL backends select settled
  unchained headers with an anti-join; late commits are picked up on a later tick.
- Merkle leaves are decoded 32-byte link hashes; parents hash the concatenated binary children;
  an odd node is promoted unchanged. Ed25519 signs JCS of the seven specified range/trust fields.
- SQL verification uses a repeatable-read snapshot. Full runs check settled header/detail
  completeness; selected or filtered runs check their links, predecessor boundaries and
  intersecting checkpoints.

## Retention operations

Only the ops login in `worm_audit_purger` may execute:

```sql
SELECT public.worm_audit_purge(now() - interval '6 years');
```

A recent/null cutoff or an incomplete expired prefix records REFUSED and returns normally.
Purge locks the audit tables against concurrent inserts, removes only a prefix closed over
all links and details of its audits, and records its last link id/hash. Detail and chain deletion
is allowed only under the function-owner identity, transaction-local purge flag, and compiled
retention cutoff. An app session setting that flag gets no deletion authority.

Lookups cannot change id/name or be deleted/truncated. The runtime role may update only the
lookup label/dates through column grants; table-level UPDATE stays revoked. With normal grants,
PostgreSQL rejects prohibited runtime writes as SQLSTATE 42501 before executing a trigger.
The second layer (triggers) returns `P0001` / `worm_audit:` even if someone grants wider DML
rights. The qbit maps those errors to a value-free user-facing message.

Verification starts from the latest successful purge anchor. Checkpoint signatures still verify
after purge, but Merkle recomputation of a purged/partly purged checkpoint requires its sealed
export and is reported as a warning. Seal and verify exports before exercising retention
removal in production. Superusers/owners can disable triggers;
protect signing keys and keep public-key pins outside the database.

## Sealed exports

Install qbit-object-storage and configure `exportBucketAlias` (default `worm_audit`) as a
`BucketRole.BACKUP` bucket. **Object Lock must be enabled when the bucket is created**.
The exporter requires the bucket's `OBJECT_LOCK` capability to be `SUPPORTED`; run the
object-storage read-only capability probe during setup. Unknown, partial and unsupported
capabilities all refuse sealing. Every object receives the effective `export_lock_mode` and retention until sealing time plus
`export_retention_days` (GOVERNANCE and 30 days by default), checked by HEAD after PUT. The
export row records both values. Verification checks that historical mode and retain-until,
regardless of subsequent settings changes. Missing GOVERNANCE objects are reported as breaks
with a possible administrator bypass-removal explanation.

The runtime IAM policy needs `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`,
`s3:GetObjectRetention`, `s3:PutObjectRetention`, and
`s3:GetBucketObjectLockConfiguration`. Grant no delete or governance-bypass access.
The storage bucket's upload size limit must accommodate the largest daily JSONL file.
Retention protects object versions; protect the storage volumes and maintain off-site copies too.

At 02:00 UTC, or through **Export now**, the exporter takes the chainer's writer lock and
seals links after the previous export through the latest checkpoint. The first export starts
after the purge anchor, or at genesis. No new checkpoint produces an explicit "Nothing to
seal" Result. If retention has removed an unexported gap, or a range cannot be proven by
complete signed checkpoints, sealing refuses rather than recording incomplete evidence.
Other database backends require a single writer JVM, as in phase (a).

Keys use `<exportPrefix>/<yyyy>/<MM>/<dd>/<from>-<to>/` with a UTC date:

- `links.jsonl`: JCS lines containing `link` identifiers/hashes and the embedded canonical
  `content` document exactly as hashed.
- `checkpoints.jsonl`: JCS checkpoint envelopes including signatures and public keys.
- `manifest.json`: JCS `worm-audit-export/1` with `fromLinkId`, `toLinkId`, `linkCount`,
  `checkpointCount`, `files` (filename to SHA-256), `headHash`, `prevManifestSha256`,
  `qbitVersion`, and `createdAt`.

Files are streamed through temporary disk storage with 1,000-link pages and batched content
fetches, then removed. Only ids, hashes and object metadata enter the export catalog.
The `object_versions` text column pins each upload's returned version id in a JCS JSON
object keyed by `checkpoints.jsonl`, `links.jsonl`, and `manifest.json`. Sealing refuses
missing version ids or a different version in the retention HEAD response, leaving no
catalog row and raising the export failure alert.
Partial upload failures leave no catalog row; retained orphan objects may remain. Retrying
can create new locked versions under the same keys. Failures raise `wormaudit.export.failed`
with dedup key `export`; success resolves it. Every scheduled run emits
`wormaudit.export.daily`.

**Verify sealed export** accepts one or several selected records. It downloads and checks
the object hashes, retention, manifest chain, link hashes, pinned checkpoint signatures and
Merkle roots, then compares the sealed content and link metadata against a live database
snapshot. Differences name exact link/audit ids without printing audit values. Each export
gets its own `SEALED_EXPORT` verification row. Purged prefixes verify from the sealed copy
alone and receive an INFO line. Verification does not write restored audit rows.

Verification compares every current HEAD version to the catalog and reports an ERROR for
any overwrite, even when the replacement bytes are identical. It then reads the recorded
sealed versions, so retained evidence remains verifiable after an overwrite; the overall
verification still fails because the overwrite is a break. Missing catalog versions fail
closed. RC.2's `StorageBucket.get` has no version parameter, so the adapter uses the public
`ObjectStorageRuntime.connection(...).client()` accessor for an explicit S3 version GET,
reusing its connection, key normalization and rate limiter and checking the response version.
No object-storage change is required; this adapter depends on RC.2's public internal runtime
accessors. The storage credentials need `s3:GetObjectVersion` in addition to the existing
upload, HEAD and listing permissions.

## Build and acceptance

```powershell
./mvnw.cmd -o verify
```

Checkstyle and JaCoCo gates (70% instructions, 90% classes) run without Docker. Memory and H2
tests cover canonical vectors, signatures, rollback, exact coverage, late arrivals/details,
verification findings, PHI tokenization, process summaries, permissions, and the alerts SPI.
The PHI stand-in uses RC.5 `AuditActionCustomizerInterface.customizeInput` before insertion;
classification is test-local because RC.5 lacks `DataClassification`.

PostgreSQL acceptance uses `postgres:16-alpine`, applies the DDL twice and tests grants,
triggers, purge, real QQQ RDBMS chaining, superuser tamper, and 8 writers / 3 chainers.
It skips automatically without Docker locally and fails if **any** `CI` environment value is set.
On a Docker-enabled coordinator (image already available if running without network):

```powershell
$env:CI = 'true'
./mvnw.cmd -o '-Dtest=PostgresAcceptanceTest' test
./mvnw.cmd -o verify
```

MinIO export acceptance uses the same `RequiresDockerCondition`. It checks GOVERNANCE
with 30-day retention and a COMPLIANCE export, denied version deletion (without bypass for GOVERNANCE), overwrite version preservation, export verification,
exact live-tamper findings through the record action, and refusal of a bucket without lock:

```powershell
$env:CI = 'true'
./mvnw.cmd -o '-Dtest=MinioExportAcceptanceTest' test
```

The default MinIO image is pinned to the same Chainguard digest as object-storage's tests.
Override it with `-Dqqq.test.minioImage=<image>` when necessary. Images must already be
available for a completely network-free Docker run.

POSIX equivalents: `CI=true ./mvnw -o -Dtest=MinioExportAcceptanceTest test`,
`CI=true ./mvnw -o -Dtest=PostgresAcceptanceTest test` and
`CI=true ./mvnw -o verify`. No commits, publishing or deployment are part of these commands.

## License

[Apache License 2.0](LICENSE). Copyright Kingsrook, LLC.

### Physical columns and bounded polling

`WormAuditDdl.postgres(config)` renders table names only. Core physical columns
must be snake_case: `audit.id`, `audit.timestamp`, `audit_detail.id`,
`audit_detail.audit_id`, `audit_table.id/name/label/create_date/modify_date`, and
`audit_user.id/name/create_date/modify_date`. QInstance field backend-name
customizations do not change this migration; adapt the reviewed SQL before
applying it if your schema differs. UTC values in `timestamp without time zone`
and `timestamptz` are both supported.

`lateDetailLookbackHours` defaults to **24** (positive hours). Each PostgreSQL
poll checks uncovered details whose chained header timestamp lies in
`[cutoff - lookback, cutoff)`. The daily full verifier reports omissions outside
that window. Initial header details are always chained, including overflow
chunks. Checkpoints contain at most `checkpointEveryLinks` links; multiple full
ranges can be signed per tick. Verification uses 1,000-link keyset pages.

Full verification holds at most one 1,000-link page and one checkpoint range of hashes.
SQL completeness uses bounded offender queries; other persistent backends use repeated bounded
scans. Only the memory backend uses a full coverage index.
Full verification retains at most 1,000 exact break diagnostics and 100 warnings,
while persisting the total break count. SQL completeness counts all offenders
and reports the first 100 header ids and first 100 detail ids. This keeps a badly
corrupted chain from exhausting verifier memory.
