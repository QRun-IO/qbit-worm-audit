# Upgrading qbit-worm-audit

## Table help bundle (unreleased)

Nothing to do. The qbit applies `help/qbit-worm-audit.yaml` at the end of `produce()`, filling only help slots the host has not set. No schema or seed changes: the settings row is still seeded by the database script (changeset `worm-audit:10`) and nothing else is seeded.

`WormAuditSettings.seed(config)` was removed (dead code). A host that called it should rely on the database script's seed; the settings reader falls back to the configured values while the row is absent.
