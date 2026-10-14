# QBit WORM Audit

Write-once, read-many (WORM) audit for QQQ applications. The QQQ core audit tables (`audit`, `audit_detail`) and this qbit's own tables become append-only at the database level, every audit row is linked into a hash chain with periodic signed checkpoints, a verification action and a daily job detect tampering, and new audit rows are sealed into an S3 bucket with Object Lock in COMPLIANCE mode (default retention 6 years, the HIPAA audit-record retention). Audit content is hashed and sealed exactly as core writes it; with qbit-secured-data, PHI field values in audit details are already HMACs, so no raw PHI reaches the chain or the sealed copies. This repository currently contains the compiling scaffold; the design is in [docs/DESIGN.md](docs/DESIGN.md) once the spec PR lands.

## Requirements

Java 21 and QQQ 4.1.0-RC.5 or later. PostgreSQL is the supported database for the append-only enforcement. The Maven wrapper pins Maven 3.9.11.

## Install

```xml
<dependency>
   <groupId>com.kingsrook.qbits</groupId>
   <artifactId>qbit-worm-audit</artifactId>
   <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Tables and permissions

Planned tables (none are produced yet): `worm_audit_chain`, `worm_audit_checkpoint`, `worm_audit_export`, `worm_audit_verification`, `worm_audit_purge`. Backend names match table names. Permissions use the full `worm_audit` prefix.

## Configuration

`WormAuditQBitConfig` exposes an optional `tableMetaDataCustomizer` and `retentionYears` (default 6).

## Adopting in another app

```java
new WormAuditQBitProducer()
   .withQBitConfig(new WormAuditQBitConfig())
   .produce(qInstance);
```

Production currently registers the QBit identity and config only. Database changesets, the object-storage bucket and the alert wiring are documented with each phase.

## Build

```bash
./mvnw compile
./mvnw test
./mvnw verify
```

Verification includes Checkstyle and JaCoCo gates of 70% instructions and 90% classes. On Windows, use `./mvnw.cmd`.

## License

[Apache License 2.0](LICENSE). Copyright Kingsrook, LLC.
