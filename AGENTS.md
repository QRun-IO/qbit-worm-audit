# AGENTS.md

Guidance for coding agents working in this repository.

## Overview

QBit WORM Audit makes QQQ audit records write-once: database-enforced append-only audit tables (Postgres triggers plus an INSERT/SELECT-only app role), a hash chain over every audit row with signed checkpoints, a verification action and daily job, and sealed JSONL exports to an S3 Object Lock (COMPLIANCE) bucket through qbit-object-storage. Design: `docs/DESIGN.md`.

## Build commands

```bash
./mvnw compile
./mvnw test
./mvnw verify  # Checkstyle; JaCoCo: 70% instructions, 90% classes
```

Use the Maven 3.9.11 wrapper (Java 21); Maven 3.10 cannot read the parent POM. On Windows use `./mvnw.cmd`.

## Architecture

Package: `com.kingsrook.qbits.wormaudit`. Entry point: `WormAuditQBitProducer implements QBitMetaDataProducer<WormAuditQBitConfig>`. Config exposes `tableMetaDataCustomizer` and `retentionYears` (default 6).

## Invariants and naming

- Audit rows are never updated or deleted by the application; the only removal path is the audited retention purge through a separate database role, after the retention date.
- The chain and the sealed exports hash exactly what core wrote. Never add raw PHI to chain rows, checkpoints, exports, logs or alerts.
- Tables use lowercase snake_case with the `worm_audit_` prefix; backend names equal table names. Permissions use the full `worm_audit` prefix. Processes are table or record actions, never navigation entries.

## Code style

3-space indent, next-line braces, `return (x);`, flower-box Javadoc on classes and methods, fluent `withX()` setters. Follow `checkstyle/` and `CODE_STYLE.md`.

## Dependencies

Parent: `com.kingsrook:qbit-build-parent:2.0.0`. QQQ BOM: `4.1.0-RC.5` (default-active `qqq-snapshot` profile).

## Release flow

CircleCI uses `kingsrook/qqq-orb@0.6.8`: develop publishes SNAPSHOTs, release/* publishes RCs, and only `vX.Y.Z` GA tags publish releases. Hotfix branches run tests only; never push `hotfix/*` or `release/*` by hand. RC automation uses workflow_dispatch or a merged develop PR labelled `release:rc`. Feature branches start from develop and return by PR. Never publish manually.
