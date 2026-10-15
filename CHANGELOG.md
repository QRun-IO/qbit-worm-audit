# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `worm-audit:13` failed with `permission denied for function worm_audit_purge` when the migrating role owns the function but had revoked its own EXECUTE (a runtime role that owns the schema, as on CNPG; PostgreSQL refuses `CREATE OR REPLACE` then). The changeset now grants EXECUTE back to the migrating role only if it lacks it, replaces the function, and revokes it again in the same transaction. Found by Website-Backend's CNPG-shaped changelog test.
- `worm-audit:13` had a comment line starting with `-- changeset`, which Liquibase formatted-SQL parsing rejects as a malformed directive. The comment is reworded, and `CanonicalAndCryptoTest` now requires every `-- changeset` line to be a real directive.
- Chain writer database load. Each 30-second tick re-read the whole late-detail lookback (24 h of `audit_detail`) and probed the GIN array index once per detail (18.4 s and 1.78M buffer hits per tick on a 120k-detail production database), and re-scanned every settled audit header for the unchained anti-join. Coverage now lives in `worm_audit_chain_detail` (`worm-audit:13`): one insert-only row per covered detail, written by the chain trigger in the same statement as its link and backfilled from the existing chain, so the late-detail check is a primary-key probe. Each tick also reads only ids above per-JVM sweep floors (rows settled since the last complete sweep); after a restart and once an hour a tick sweeps everything, as before. Link hash inputs, `detail_ids`, the verifier and exports are unchanged.
- The chain trigger's overlap check (`EXISTS ... && ...`) ran as a cached generic plan that sequentially scanned all of `worm_audit_chain` for every inserted link (55k sequential scans, 1.2B tuples read in production, about 80 ms per link and growing). The trigger now inserts the coverage rows and lets their primary key reject a detail covered twice.
- Verification counts detail coverage by aggregating the chain's own detail lists once instead of one index probe per detail, and breaks when the coverage table disagrees with the chain.

- Startup on hosts whose default authentication requires a token (OAuth2, Auth0): `produce()` read the settings singleton under a plain tokenless `QSession`, which failed session validation (`JWTDecodeException: The token is null`) and stopped the host. The startup read now runs as the core `QSystemUserSession`, still honoring the persisted schedules. `TokenRequiredHostTest` runs production under a token-required test authentication module.

### Added

- Foreign keys (`worm-audit:11-12`), `ON DELETE RESTRICT` only: chain link -> core audit header, sealed export -> its first and last checkpoints, export verification -> its export, with their indexes. Link references (ranges, break link, purge anchor) stay unconstrained because the retention purge deletes the links they outlive. Pre-existing orphans are copied to `qqq_fk_quarantine` (`KEPT`), never modified, and leave that constraint `NOT VALID`. Re-apply the rendered DDL (idempotent).
- Guided empty states: `help/qbit-worm-audit.yaml` (QQQ help-bundle format) gives the app and all six tables a summary and a "How rows get created" section, applied by the `WormAuditHelp` stand-in (`STAND-IN(core=QRun-IO/qqq#1198, removeBy=4.1.0-RC.7)`) without replacing host help. `WormAuditTablesGuardrailTest` pins runtime use, seeding or a documented reason, and help for every table; `WormAuditSettingsSeedTest` runs the script's settings seed on H2.
- RC.2 settings: editable, FIELD-audited singleton with insert-only defaults, validation, separate edit permission and a 30-second effective-settings cache. Schedules load at startup.
- GOVERNANCE exports with 30-day default retention; per-export retention verification, administrator-bypass diagnostics, home warnings and documented COMPLIANCE transition.
- New `worm-audit:10` settings migration; historical changesets remain unchanged.

- Phase (c): configurable WORM Audit app home, full-width summary widget and optional host health card; permission-aware navigation and content-free, responsive light/dark summaries.
- Chain backlog/settling counts, verification and export record links, sealed-range gaps/lag, retention eligibility and recent purge/refusal history.
- PostgreSQL guard/ownership/purge-function diagnostics, signing/trust warnings, tri-state Object Lock capability and stale daily-verification warnings.
- Test-scope Next UI demo with synthetic tokenized patient notes, genuine verification failure/recovery, signed checkpoints, sealed memory exports and documented simulated purges.
- Home privacy/permission/empty-state tests, memory/H2 summary tests and Docker-gated PostgreSQL setup-warning acceptance.

- Phase (a): PostgreSQL append-only tables/triggers, safe DDL renderer, retention purge with immutable refusal/anchor records, and runtime grants.
- Canonical audit v1 documents, contiguous hash chain with late-detail coverage, pinned Ed25519 checkpoints and binary Merkle roots.
- Snapshot verification, streamed ETL Review/Result action, scheduled chaining/daily verification, and core QAlerts raise/resolve/heartbeat integration.
- Read-only metadata, WORM Audit table navigation, record range references and child lists; reflective RC.6 assistant deny registration.
- Offline memory/H2 acceptance, real pre-insert PHI canary hook, and PostgreSQL Testcontainers acceptance with CI-strict Docker availability.
- Adoption, app-home, demo and operations documentation.

### Fixed

- Keep runtime signing/trust objects and storage suppliers out of serialized metadata so signed-chain record child lists render successfully.

### Deprecated

- `WormAuditSettings.seed(config)` is deprecated for PostgreSQL hosts, whose database script (`worm-audit:10`) already seeds row 1; it remains supported for memory and H2 hosts. `read()` falls back to the configured values while the row is absent.
