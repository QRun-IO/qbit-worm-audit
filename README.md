# QBit WORM Audit

Phase (a) provides PostgreSQL append-only enforcement, an asynchronous audit hash chain,
Ed25519 checkpoints, a verification action, and daily verification with core QAlerts signals.
It hashes exactly the audit values core stored; it does not read application records or
secured-data keys. Sealed exports and the app home are later phases. The export table and
range references are present as integration hooks; no export job or home widgets are installed.

Requires Java 21, Maven wrapper 3.9.11 and QQQ 4.1.0-RC.5. PostgreSQL provides enforcement;
memory/H2 support tamper-evidence tests without database enforcement.

## Tables and permissions

All sidecar tables use the configured host backend, snake_case fields, BIGINT identifiers,
record sections, and full table-name permissions. They do not audit themselves. The app lists
Verifications, Sealed Exports, Checkpoints, Audit Chain, and Purges in that order.

| Table | Purpose | Permission |
|---|---|---|
| `worm_audit_verification` | Immutable USER/SCHEDULE results | `worm_audit_verification.read` |
| `worm_audit_export` | Reserved sealed-export catalog | `worm_audit_export.read` |
| `worm_audit_checkpoint` | Signed ranges and Merkle roots | `worm_audit_checkpoint.read` |
| `worm_audit_chain` | Contiguous links and explicit detail coverage | `worm_audit_chain.read` |
| `worm_audit_purge` | Refusals, removal counts and retention anchors | `worm_audit_purge.read` |

`worm_audit.verify` authorizes the standard streamed ETL **Verify audit chain** action.
Processes are attached to the chain table or scheduled; none is a navigation entry.
Insert/update/delete capabilities are absent on sidecar tables; update/delete capabilities
are removed from all four core audit tables. Internal appends use an explicit permission bypass.
Checkpoint, export and verification record screens have a bounded chain-link child list;
range endpoints and export/checkpoint references link to their records.

The table metadata customizer can configure host ESB publications. Quick Search registration
is host-owned through `QuickSearchQBitConfig.searchableTables`; add all five tables.
Verification inserts use QQQ's record-change listener SPI (as will phase-(b) export inserts),
so an installed ESB publisher receives those events when the host configures its destinations
on these two tables. The qbit defines no destination and configures no chain-link publication.

## Configuration

| Field | Default / contract |
|---|---|
| `backendName` | Required; core and sidecar audit tables must use this backend |
| `retentionYears` | 6; compiled into the migration, not changed by a runtime flag |
| `signingKey` | Optional `Supplier<SigningKey>`; `SigningKey(keyId, PrivateKey)` |
| `trustedPublicKeys` | `Map<String, PublicKey>`; must contain the signing key's public key |
| `chainIntervalSeconds` | 30 |
| `settleHorizonSeconds` | 60 (zero allowed) |
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
RC.5's alert-type metadata validator disallows underscores, so the qbit sends the specified
`worm_audit.chain.break` signal without declaring incompatible alert-type metadata. `QAlerts`
still dispatches it to the sink (or its logging fallback). Every scheduled verification sends
`worm_audit.verify.daily`; FAIL raises with the first break and verification record reference;
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
  intersecting checkpoints. Full verification currently materializes link metadata in memory.

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
export and is reported as a warning. Sealed exports are phase (b); preserve external evidence
before exercising retention removal in production. Superusers/owners can disable triggers;
protect signing keys and keep public-key pins outside the database.

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

POSIX equivalents: `CI=true ./mvnw -o -Dtest=PostgresAcceptanceTest test` and
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

Full verification retains at most 1,000 exact break diagnostics and 100 warnings,
while persisting the total break count. SQL completeness counts all offenders
and reports the first 100 header ids and first 100 detail ids. This keeps a badly
corrupted chain from exhausting verifier memory.
