# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
