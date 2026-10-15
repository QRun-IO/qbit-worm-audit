# Upgrading qbit-worm-audit

## Detail coverage table (0.1.0-RC.4)

Apply changeset `worm-audit:13` from the rendered DDL (or your copy of it) before or with the new jar. It takes the chain advisory lock, creates `worm_audit_chain_detail` with its append-only guards and grants, backfills it from the existing chain, and replaces `worm_audit_reject()`, `worm_audit_detail_coverage()` and `worm_audit_purge()`. The jar requires the table: its chain writer reads it every tick. The GIN index `worm_audit_chain_detail_coverage` is no longer used but is kept so an RC.3 writer still running during a rolling deploy keeps an indexed probe; a later changeset drops it. Memory and H2 hosts need no migration beyond creating the new table (the writer fills it).

## Table help bundle (unreleased)

Nothing to do. The qbit applies `help/qbit-worm-audit.yaml` at the end of `produce()`, filling only help slots the host has not set. No schema or seed changes: the settings row is still seeded by the database script (changeset `worm-audit:10`) and nothing else is seeded.

`WormAuditSettings.seed(config)` is now `@Deprecated` for PostgreSQL hosts (the script seeds row 1). It still works and remains the way for memory and H2 hosts to create row 1. The settings reader falls back to the configured values while the row is absent.
