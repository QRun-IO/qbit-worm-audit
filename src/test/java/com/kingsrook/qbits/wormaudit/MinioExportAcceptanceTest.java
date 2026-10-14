/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2025.  Kingsrook, LLC
 * 651 N Broad St Ste 205 # 6917 | Middletown DE 19709 | United States
 * contact@kingsrook.com
 * https://github.com/Kingsrook/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.wormaudit;


import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import com.kingsrook.qbits.objectstorage.ObjectStorageQBitConfig;
import com.kingsrook.qbits.objectstorage.api.Capability;
import com.kingsrook.qbits.objectstorage.api.CapabilityStatus;
import com.kingsrook.qbits.objectstorage.api.ListRequest;
import com.kingsrook.qbits.objectstorage.api.ObjectStorage;
import com.kingsrook.qbits.objectstorage.config.AddressingStyle;
import com.kingsrook.qbits.objectstorage.config.BucketRole;
import com.kingsrook.qbits.objectstorage.config.ChecksumMode;
import com.kingsrook.qbits.objectstorage.config.ProviderType;
import com.kingsrook.qbits.objectstorage.config.StorageBucketConfig;
import com.kingsrook.qbits.objectstorage.config.StorageConnectionConfig;
import com.kingsrook.qbits.objectstorage.internal.CapabilityProbe;
import com.kingsrook.qbits.objectstorage.internal.CapabilityStore;
import com.kingsrook.qbits.objectstorage.internal.ObjectStorageRuntime;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.export.ExportFiles;
import com.kingsrook.qbits.wormaudit.export.ObjectStorageSealedStore;
import com.kingsrook.qbits.wormaudit.export.SealedExportVerifier;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.ExportProcesses;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.tamper;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Real Object Lock acceptance. Missing Docker skips locally and fails in CI.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
class MinioExportAcceptanceTest
{
   /*******************************************************************************
    ** Production adapter, COMPLIANCE retention, version preservation and UI findings.
    *******************************************************************************/
   @Test
   void lockedRoundTripVersionRetentionLiveTamperAndUnsupportedBucket() throws Exception
   {
      String image = System.getProperty("qqq.test.minioImage",
         "cgr.dev/chainguard/minio@sha256:dc455cdd4db6e390b1b26514f15ff37681a777bf8dab41aac445a0259f751e56");
      try(GenericContainer<?> minio = new GenericContainer<>(image)
         .withEnv("MINIO_ROOT_USER", "worm-test-access").withEnv("MINIO_ROOT_PASSWORD", "worm-test-secret")
         .withCommand("server", "/tmp/minio-data").withExposedPorts(9000)
         .waitingFor(Wait.forHttp("/minio/health/live").forPort(9000).withStartupTimeout(Duration.ofMinutes(2))))
      {
         minio.start();
         String endpoint = "http://" + minio.getHost() + ":" + minio.getMappedPort(9000);
         try(S3Client s3 = S3Client.builder().endpointOverride(URI.create(endpoint)).region(Region.US_EAST_1).forcePathStyle(true)
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("worm-test-access", "worm-test-secret")))
            .requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED)
            .responseChecksumValidation(ResponseChecksumValidation.WHEN_REQUIRED).build())
         {
            s3.createBucket(b -> b.bucket("worm-locked").objectLockEnabledForBucket(true));
            s3.createBucket(b -> b.bucket("worm-plain"));
            var config = ChainVerificationTest.signed();
            var instance = init(config);
            AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(ProcessesAndAlertsTest.Sink.class));
            ProcessesAndAlertsTest.Sink.raised.clear();
            System.setProperty("worm.test.access", "worm-test-access");
            System.setProperty("worm.test.secret", "worm-test-secret");
            ObjectStorage.configureStandalone(new ObjectStorageQBitConfig().withBackendName("memory")
               .withAllowedSecretRefPatterns(List.of("prop.worm.test.*"))
               .withConnection(new StorageConnectionConfig("minio").withProviderType(ProviderType.MINIO).withEndpoint(endpoint)
                  .withRegion("us-east-1").withAddressingStyle(AddressingStyle.PATH).withChecksumMode(ChecksumMode.WHEN_REQUIRED)
                  .withAccessKeyRef("${prop.worm.test.access}").withSecretKeyRef("${prop.worm.test.secret}"))
               .withBucket(new StorageBucketConfig("worm_audit").withConnection("minio").withBucketName("worm-locked").withRole(BucketRole.BACKUP).withIndexed(false))
               .withBucket(new StorageBucketConfig("plain").withConnection("minio").withBucketName("worm-plain").withRole(BucketRole.BACKUP).withIndexed(false)));
            CapabilityProbe.probeConnection("minio", false);
            assertThat(ObjectStorage.asSystem("test", "1").bucket("worm_audit").capability(Capability.OBJECT_LOCK)).isEqualTo(CapabilityStatus.SUPPORTED);
            assertThat(ObjectStorage.asSystem("test", "1").bucket("plain").capability(Capability.OBJECT_LOCK)).isEqualTo(CapabilityStatus.UNSUPPORTED);
            audit(1);
            detail(1, 1);
            new WormAuditChainer(config).chainOnce();
            Instant now = Instant.now();
            var exported = new SealedExporter(config).run("USER", now);
            assertThat(exported.failed()).as(exported.message()).isFalse();
            var row = exported.row();
            var storage = new ObjectStorageSealedStore("worm_audit", "acceptance");
            assertThat(storage.list(ListRequest.prefix(row.getValueString("object_prefix"))).getItems()).hasSize(3);
            var verifier = new SealedExportVerifier(config);
            assertThat(verifier.verify(row, "USER").result().passed()).isTrue();
            for(String name : ExportFiles.NAMES)
            {
               String key = row.getValueString("object_prefix") + name;
               var head = storage.head(key);
               assertThat(head.getLockMode()).isEqualTo("COMPLIANCE");
               assertThat(Duration.between(now.atZone(java.time.ZoneOffset.UTC).plusYears(6).toInstant(), head.getLockRetainUntil()).abs()).isLessThan(Duration.ofSeconds(2));
               String originalVersion = head.getVersionId();
               assertThat(originalVersion).isNotBlank();
               assertThat(ExportFiles.parse(row.getValueString("object_versions").getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                  .containsEntry(name, originalVersion);
               assertThatThrownBy(() -> s3.deleteObject(b -> b.bucket("worm-locked").key(key).versionId(originalVersion)))
                  .isInstanceOf(S3Exception.class);
               byte[] original = s3.getObjectAsBytes(b -> b.bucket("worm-locked").key(key).versionId(originalVersion)).asByteArray();
               // S3 overwrites create new versions; they cannot replace the locked version.
               var replacement = s3.putObject(b -> b.bucket("worm-locked").key(key).objectLockMode("COMPLIANCE")
                  .objectLockRetainUntilDate(row.getValueInstant("retain_until")), RequestBody.fromString("different replacement bytes"));
               assertThat(replacement.versionId()).isNotEqualTo(originalVersion);
               assertThat(s3.getObjectAsBytes(b -> b.bucket("worm-locked").key(key).versionId(originalVersion)).asByteArray()).isEqualTo(original);
               try(var sealed = storage.getVersion(key, originalVersion))
               {
                  assertThat(sealed.readAllBytes()).isEqualTo(original);
               }
               var report = verifier.verify(row, "USER");
               assertThat(report.result().passed()).isFalse();
               assertThat(report.result().getLinksChecked()).isEqualTo(1);
               assertThat(report.result().getBreaks()).allSatisfy(b -> assertThat(b.reason()).contains("was overwritten after sealing"));
               assertThat(report.result().getBreaks().toString()).contains("object " + name + " was overwritten after sealing (current version "
                  + replacement.versionId() + ", sealed version " + originalVersion + " is still retained under Object Lock)");
            }
            tamper("auditDetail", 1, "newValue", "tampered live value");
            var load = new ExportProcesses.VerifyLoad();
            load.runOnePage(new RunBackendStepInput().withRecords(List.of(row)), new RunBackendStepOutput());
            assertThat(load.getProcessSummary(new RunBackendStepOutput(), true).toString())
               .contains("ERROR", "link 1 (audit 1): live content differs from the sealed copy");
            tamper("auditDetail", 1, "newValue", "new");
            audit(2);
            new WormAuditChainer(config).chainOnce();
            config.withExportBucketAlias("plain");
            var failed = new SealedExporter(config).run("SCHEDULE", Instant.now());
            assertThat(failed.failed()).isTrue();
            assertThat(failed.message()).contains("does not support Object Lock");
            assertThat(STORE.all(WormAuditTables.EXPORT)).hasSize(1);
            assertThat(ProcessesAndAlertsTest.Sink.raised).hasSize(1);
         }
         finally
         {
            ObjectStorageRuntime.reset();
            CapabilityStore.clearCache();
            System.clearProperty("worm.test.access");
            System.clearProperty("worm.test.secret");
         }
      }
   }
}

