# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
