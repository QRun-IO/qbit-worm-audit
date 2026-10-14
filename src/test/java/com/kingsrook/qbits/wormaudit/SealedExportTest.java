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


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.objectstorage.api.ListRequest;
import com.kingsrook.qbits.objectstorage.api.ObjectSummary;
import com.kingsrook.qbits.objectstorage.api.Page;
import com.kingsrook.qbits.objectstorage.api.StoredObject;
import com.kingsrook.qbits.wormaudit.canonical.Jcs;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.export.ExportFiles;
import com.kingsrook.qbits.wormaudit.export.SealedExportVerifier;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.export.SealedStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.ExportProcesses;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunInput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunOutput;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.remove;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.tamper;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Offline sealed-export contract, corruption, retention, batching and UI tests.
 *******************************************************************************/
class SealedExportTest
{
   static final Instant NOW = Instant.parse("2026-10-14T02:00:00Z");
   WormAuditQBitConfig config;
   MemorySealedStore storage;

   /*******************************************************************************
    ** Tiny object boundary; bytes exist only in tests.
    *******************************************************************************/
   static class MemorySealedStore implements SealedStore
   {
      final Map<String, byte[]> objects = new LinkedHashMap<>();
      final Map<String, StoredObject> heads = new LinkedHashMap<>();
      final Map<String, Map<String, byte[]>> history = new LinkedHashMap<>();
      int nextVersion;
      String missingVersion;
      boolean omitVersion;
      boolean racePut;
      boolean supported = true;
      String echoMode = "COMPLIANCE";
      long shortenSeconds;
      int failPut;

      @Override
      public boolean supportsLock()
      {
         return (supported);
      }

      @Override
      public String put(String key, Path file, Instant until) throws Exception
      {
         if(failPut > 0 && objects.size() + 1 == failPut)
         {
            throw (new IllegalStateException("CANARY-PRIVATE-PROVIDER-TEXT"));
         }
         if(objects.containsKey(key))
         {
            history.computeIfAbsent(key, k -> new LinkedHashMap<>()).put(heads.get(key).getVersionId(), objects.get(key));
         }
         String version = omitVersion ? missingVersion : "v" + ++nextVersion;
         objects.put(key, Files.readAllBytes(file));
         heads.put(key, new StoredObject().withKey(key).withVersionId(racePut ? "replacement" : version)
            .withLockMode(echoMode).withLockRetainUntil(until.minusSeconds(shortenSeconds)));
         return (version);
      }

      @Override
      public StoredObject head(String key)
      {
         return (heads.get(key));
      }

      @Override
      public InputStream getVersion(String key, String versionId)
      {
         byte[] bytes = versionId.equals(heads.get(key).getVersionId()) ? objects.get(key) : history.get(key).get(versionId);
         return (new ByteArrayInputStream(bytes));
      }

      @Override
      public Page<ObjectSummary> list(ListRequest request)
      {
         return (new Page<ObjectSummary>().withItems(objects.keySet().stream().filter(k -> k.startsWith(request.getPrefix()))
            .map(k -> new ObjectSummary().withKey(k)).toList()));
      }
   }


   /*******************************************************************************
    ** Exercise setUp.
    *******************************************************************************/
   @BeforeEach
   void setUp() throws Exception
   {
      config = ChainVerificationTest.signed();
      var instance = init(config);
      storage = new MemorySealedStore();
      ProcessesAndAlertsTest.Sink.raised.clear();
      ProcessesAndAlertsTest.Sink.resolved.clear();
      ProcessesAndAlertsTest.Sink.beats.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(ProcessesAndAlertsTest.Sink.class));
   }


   QRecord seal() throws Exception
   {
      new WormAuditChainer(config).chainOnce(NOW);
      var result = new SealedExporter(config, storage).run("USER", NOW);
      assertThat(result.failed()).as(result.message()).isFalse();
      assertThat(result.row()).isNotNull();
      return (result.row());
   }


   SealedExportVerifier.Report verify(QRecord row) throws Exception
   {
      return (new SealedExportVerifier(config, storage).verify(row, "USER"));
   }


   String findings(QRecord row) throws Exception
   {
      return (verify(row).result().getBreaks().toString());
   }


   /*******************************************************************************
    ** Exercise canonicalGoldenFilesAndRoundTrip.
    *******************************************************************************/
   @Test
   void canonicalGoldenFilesAndRoundTrip() throws Exception
   {
      audit(1);
      detail(1, 1);
      QRecord row = seal();
      String prefix = "worm-audit/2026/10/14/1-1/";
      assertThat(row.getValueString("object_prefix")).isEqualTo(prefix);
      String content = "{\"audit\":{\"clientChannel\":null,\"id\":1,\"message\":\"Record was Edited\",\"recordId\":\"17\",\"table\":\"cms_page\",\"timestamp\":\"2020-01-02T03:04:06.123456Z\",\"user\":\"james\"},\"details\":[{\"fieldName\":\"title\",\"id\":1,\"message\":\"Changed Title\",\"newValue\":\"new\",\"oldValue\":\"old\"}],\"v\":1}";
      String hash = Hashes.link(Hashes.GENESIS, content.getBytes(StandardCharsets.UTF_8));
      String golden = "{\"content\":" + content + ",\"link\":{\"auditId\":1,\"detailIds\":[1],\"id\":1,\"kind\":\"AUDIT\",\"linkHash\":\"" + hash
         + "\",\"prevHash\":\"" + Hashes.GENESIS + "\"}}\n";
      assertThat(new String(storage.objects.get(prefix + "links.jsonl"), StandardCharsets.UTF_8)).isEqualTo(golden);
      var manifest = ExportFiles.parse(storage.objects.get(prefix + "manifest.json"));
      assertThat(manifest.keySet()).containsExactly("checkpointCount", "createdAt", "files", "format", "fromLinkId", "headHash", "linkCount",
         "prevManifestSha256", "qbitVersion", "toLinkId");
      assertThat(manifest).containsEntry("format", "worm-audit-export/1").containsEntry("linkCount", 1L).containsEntry("checkpointCount", 1L)
         .containsEntry("prevManifestSha256", null).containsEntry("headHash", hash).containsEntry("createdAt", NOW.toString());
      assertThat(storage.objects.get(prefix + "manifest.json")).isEqualTo(Jcs.bytes(manifest));
      assertThat(row.getValues()).containsKeys("from_checkpoint_id", "to_checkpoint_id", "bucket_alias", "manifest_key", "manifest_sha256",
         "prev_manifest_sha256", "object_count", "byte_count", "lock_mode", "retain_until", "sealed_at");
      assertThat(row.getValueLong("byte_count")).isEqualTo(storage.objects.values().stream().mapToLong(b -> b.length).sum());
      assertThat(row.getValueInstant("retain_until")).isEqualTo(Instant.parse("2032-10-14T02:00:00Z"));
      assertThat(verify(row).result().passed()).isTrue();
      QRecord verification = STORE.last(WormAuditTables.VERIFICATION);
      assertThat(verification.getValueString("kind")).isEqualTo("SEALED_EXPORT");
      assertThat(verification.getValueLong("export_id")).isEqualTo(row.getValueLong("id"));
      assertThat(verification.getValueString("outcome")).isEqualTo("PASS");
      assertThat(ProcessesAndAlertsTest.Sink.resolved).hasSize(1);
   }


   /*******************************************************************************
    ** Every overwrite is a break while verification still uses the sealed bytes.
    *******************************************************************************/
   @Test
   void detectsOverwritesAndReadsSealedVersions() throws Exception
   {
      audit(1);
      QRecord row = seal();
      Map<String, Object> versions = ExportFiles.parse(row.getValueString("object_versions").getBytes(StandardCharsets.UTF_8));
      assertThat(versions.keySet()).containsExactly("checkpoints.jsonl", "links.jsonl", "manifest.json");
      assertThat(row.getValueString("object_versions")).isEqualTo(Jcs.string(versions));
      assertThat(STORE.get(WormAuditTables.EXPORT, row.getValueLong("id")).getValueString("object_versions"))
         .isEqualTo(row.getValueString("object_versions"));
      try(var files = new ExportFiles())
      {
         String linksKey = row.getValueString("object_prefix") + "links.jsonl";
         Files.write(files.file("links.jsonl"), storage.objects.get(linksKey));
         storage.put(linksKey, files.file("links.jsonl"), row.getValueInstant("retain_until"));
         var identical = verify(row);
         assertThat(identical.result().passed()).isFalse();
         assertThat(identical.result().getLinksChecked()).isEqualTo(1);
         assertThat(identical.result().getBreaks()).singleElement().satisfies(b ->
            assertThat(b.reason()).contains("object links.jsonl was overwritten after sealing"));
         for(String name : ExportFiles.NAMES)
         {
            String key = row.getValueString("object_prefix") + name;
            Files.writeString(files.file(name), "different bytes");
            String current = storage.put(key, files.file(name), row.getValueInstant("retain_until"));
            var report = verify(row);
            assertThat(report.result().passed()).isFalse();
            assertThat(report.result().getLinksChecked()).isEqualTo(1);
            assertThat(report.result().getBreaks()).allSatisfy(b -> assertThat(b.reason()).contains("was overwritten after sealing"));
            assertThat(report.result().getBreaks().toString()).contains("object " + name + " was overwritten after sealing (current version "
               + current + ", sealed version " + versions.get(name) + " is still retained under Object Lock)");
         }
      }
      var load = new ExportProcesses.VerifyLoad(storage);
      load.runOnePage(new RunBackendStepInput().withRecords(List.of(row)), new RunBackendStepOutput());
      assertThat(load.getProcessSummary(new RunBackendStepOutput(), true).toString()).contains("ERROR", "was overwritten after sealing");
   }


   /*******************************************************************************
    ** Unversioned uploads and upload/HEAD races cannot create a sealed catalog row.
    *******************************************************************************/
   @Test
   void refusesMissingVersionsAndUploadRaces() throws Exception
   {
      audit(1);
      new WormAuditChainer(config).chainOnce(NOW);
      storage.omitVersion = true;
      for(String version : java.util.Arrays.asList(null, "", " ", "null"))
      {
         storage.missingVersion = version;
         var result = new SealedExporter(config, storage).run("USER", NOW);
         assertThat(result.failed()).isTrue();
         assertThat(result.message()).contains("returned no version id");
         assertThat(STORE.all(WormAuditTables.EXPORT)).isEmpty();
      }
      storage.omitVersion = false;
      storage.racePut = true;
      assertThat(new SealedExporter(config, storage).run("USER", NOW).message()).contains("version changed after upload");
      assertThat(STORE.all(WormAuditTables.EXPORT)).isEmpty();
      assertThat(ProcessesAndAlertsTest.Sink.raised).hasSize(5);
   }


   /*******************************************************************************
    ** Missing catalog versions must never silently fall back to current content.
    *******************************************************************************/
   @Test
   void refusesMissingRecordedVersion() throws Exception
   {
      audit(1);
      QRecord row = seal();
      row.setValue("object_versions", "{}");
      assertThat(findings(row)).contains("object links.jsonl has no recorded sealed version id");
      row.setValue("object_versions", null);
      assertThat(verify(row).result().passed()).isFalse();
   }


   /*******************************************************************************
    ** Exercise rangeSelectionNoCheckpointContiguousAndPurgeAnchor.
    *******************************************************************************/
   @Test
   void rangeSelectionNoCheckpointContiguousAndPurgeAnchor() throws Exception
   {
      assertThat(new SealedExporter(config, storage).run("SCHEDULE", NOW).message()).isEqualTo("Nothing to seal: no new checkpoint");
      assertThat(ProcessesAndAlertsTest.Sink.beats).containsExactly("wormaudit.export.daily");
      audit(1);
      QRecord first = seal();
      assertThat(new SealedExporter(config, storage).run("USER", NOW).row()).isNull();
      audit(2);
      QRecord second = seal();
      assertThat(second.getValueLong("from_link_id")).isEqualTo(2L);
      assertThat(second.getValueString("prev_manifest_sha256")).isEqualTo(first.getValueString("manifest_sha256"));
      assertThat(verify(second).result().passed()).isTrue();

      init(config);
      STORE.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("outcome", "PURGED").withValue("anchor_link_id", 10L).withValue("anchor_hash", Hashes.GENESIS)));
      audit(11);
      QRecord anchored = seal();
      assertThat(anchored.getValueLong("from_link_id")).isEqualTo(11L);
      assertThat(anchored.getValueString("prev_manifest_sha256")).isNull();
      assertThat(verify(anchored).result().passed()).isTrue();
      STORE.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("outcome", "PURGED").withValue("anchor_link_id", 20L).withValue("anchor_hash", Hashes.GENESIS)));
      assertThatThrownBy(() -> SealedExporter.scope(STORE)).hasMessage("Unexported links were purged");
   }


   /*******************************************************************************
    ** Exercise refusesUnsupportedAndIncorrectLockEchoAndPartialUpload.
    *******************************************************************************/
   @Test
   void refusesUnsupportedAndIncorrectLockEchoAndPartialUpload() throws Exception
   {
      audit(1);
      new WormAuditChainer(config).chainOnce(NOW);
      storage.supported = false;
      assertThat(new SealedExporter(config, storage).run("SCHEDULE", NOW).message()).contains("does not support Object Lock");
      assertThat(storage.objects).isEmpty();
      storage.supported = true;
      storage.echoMode = "GOVERNANCE";
      assertThat(new SealedExporter(config, storage).run("USER", NOW).message()).contains("did not echo COMPLIANCE");
      storage.echoMode = "COMPLIANCE";
      storage.shortenSeconds = 1;
      assertThat(new SealedExporter(config, storage).run("USER", NOW).failed()).isTrue();
      storage.shortenSeconds = 0;
      storage.objects.clear();
      storage.failPut = 2;
      assertThat(new SealedExporter(config, storage).run("SCHEDULE", NOW).message()).doesNotContain("CANARY").contains("storage or database");
      assertThat(STORE.all(WormAuditTables.EXPORT)).isEmpty();
      assertThat(ProcessesAndAlertsTest.Sink.raised).hasSize(4);
      assertThat(ProcessesAndAlertsTest.Sink.beats).hasSize(2);
   }


   /*******************************************************************************
    ** Exercise tamperedObjectsBrokenManifestChainAndLockRemoval.
    *******************************************************************************/
   @Test
   void tamperedObjectsBrokenManifestChainAndLockRemoval() throws Exception
   {
      audit(1);
      QRecord first = seal();
      String key = first.getValueString("object_prefix") + "links.jsonl";
      byte[] original = storage.objects.get(key);
      storage.objects.put(key, "tampered".getBytes(StandardCharsets.UTF_8));
      assertThat(findings(first)).contains("object links.jsonl hash does not match the manifest");
      storage.objects.put(key, original);
      storage.heads.get(key).withLockMode("GOVERNANCE");
      assertThat(findings(first)).contains("lacks the recorded COMPLIANCE retention");
      storage.heads.get(key).withLockMode("COMPLIANCE");
      audit(2);
      QRecord second = seal();
      tamper(WormAuditTables.EXPORT, first.getValueLong("id"), "manifest_sha256", "f".repeat(64));
      assertThat(findings(second)).contains("prevManifestSha256 does not match");
      assertThat(findings(STORE.get(WormAuditTables.EXPORT, first.getValueLong("id")))).contains("manifest.json hash does not match");
   }


   /*******************************************************************************
    ** Exercise exactLiveDifferencesMissingRowsAndPurgedCopies.
    *******************************************************************************/
   @Test
   void exactLiveDifferencesMissingRowsAndPurgedCopies() throws Exception
   {
      audit(1);
      detail(1, 1);
      audit(2);
      QRecord row = seal();
      tamper("auditDetail", 1, "newValue", "CANARY-PRIVATE");
      assertThat(findings(row)).contains("link 1 (audit 1): live content differs from the sealed copy (sealed 2026-10-14)").doesNotContain("CANARY");
      remove(WormAuditTables.CHAIN, 2);
      assertThat(findings(row)).contains("link 2 is missing from the live chain");
      tamper(WormAuditTables.CHAIN, 1, "kind", "LATE_DETAIL");
      assertThat(findings(row)).contains("live chain kind differs");
      remove("audit", 1);
      assertThat(findings(row)).contains("live audit header is missing");
      String head = (String) ExportFiles.parse(storage.objects.get(row.getValueString("manifest_key"))).get("headHash");
      STORE.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("outcome", "PURGED").withValue("anchor_link_id", 2L).withValue("anchor_hash", head)));
      remove(WormAuditTables.CHAIN, 1);
      remove("audit", 2);
      var report = verify(row);
      assertThat(report.result().passed()).isTrue();
      assertThat(report.purged()).isEqualTo(2);
      var load = new ExportProcesses.VerifyLoad(storage);
      load.runOnePage(new RunBackendStepInput().withRecords(List.of(row)), new RunBackendStepOutput());
      assertThat(load.getProcessSummary(new RunBackendStepOutput(), true).toString()).contains("INFO", "2 links verified from the sealed copy only");
   }


   /*******************************************************************************
    ** Exercise refusesBadSourceAndDetectsMissingLiveDetails.
    *******************************************************************************/
   @Test
   void refusesBadSourceAndDetectsMissingLiveDetails() throws Exception
   {
      audit(1);
      detail(1, 1);
      new WormAuditChainer(config).chainOnce(NOW);
      tamper("auditDetail", 1, "newValue", "changed");
      assertThat(new SealedExporter(config, storage).run("USER", NOW).message()).contains("content differs at link 1");
      assertThat(storage.objects).isEmpty();
      tamper("auditDetail", 1, "newValue", "new");
      QRecord row = seal();
      remove("auditDetail", 1);
      assertThat(findings(row)).contains("link 1 (audit 1): live content is missing or invalid");
   }


   /*******************************************************************************
    ** Exercise spansPagesLateDetailsAndCheckpointBoundaries.
    *******************************************************************************/
   @Test
   void spansPagesLateDetailsAndCheckpointBoundaries() throws Exception
   {
      config.withBatchSize(1100).withCheckpointEveryLinks(500);
      for(long id = 1; id <= 1100; id++)
      {
         audit(id);
      }
      new WormAuditChainer(config).chainOnce(NOW);
      // The final 100 links need the hourly checkpoint.
      new WormAuditChainer(config).chainOnce(NOW.plusSeconds(3601));
      QRecord row = seal();
      assertThat(row.getValueLong("to_link_id")).isEqualTo(1100);
      assertThat(verify(row).result().getLinksChecked()).isEqualTo(1100);
      detail(1, 1);
      new WormAuditChainer(config).chainOnce(NOW.plusSeconds(7202));
      new WormAuditChainer(config).chainOnce(NOW.plusSeconds(10803));
      QRecord late = seal();
      assertThat(late.getValueLong("from_link_id")).isEqualTo(1101);
      assertThat(verify(late).result().passed()).isTrue();
   }


   /*******************************************************************************
    ** Exercise reviewLoadSelectionAndSchedulesUseStandardEtl.
    *******************************************************************************/
   @Test
   void reviewLoadSelectionAndSchedulesUseStandardEtl() throws Exception
   {
      var instance = com.kingsrook.qqq.backend.core.context.QContext.getQInstance();
      assertThat(config.getExportBucketAlias()).isEqualTo("worm_audit");
      assertThat(config.getExportPrefix()).isEqualTo("worm-audit");
      assertThat(instance.getProcess(ExportProcesses.EXPORT).getTableName()).isEqualTo(WormAuditTables.EXPORT);
      assertThat(instance.getProcess(ExportProcesses.VERIFY).getMinInputRecords()).isEqualTo(1);
      assertThat(instance.getProcess(ExportProcesses.DAILY).getSchedule().getCronTimeZoneId()).isEqualTo("UTC");
      assertThat(instance.getProcess(ExportProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo("0 0 2 * * ?");
      var output = new RunBackendStepOutput();
      var input = new RunBackendStepInput().withRecords(List.of(new QRecord().withValue("id", 0L)));
      var extract = new ExportProcesses.ExportExtract();
      assertThat(extract.doCount(input)).isEqualTo(1);
      extract.setRecordPipe(new com.kingsrook.qqq.backend.core.actions.reporting.RecordPipe());
      extract.run(input, output);
      var review = new ExportProcesses.ExportReview();
      review.runOnePage(input, output);
      assertThat(review.getProcessSummary(output, false).toString()).contains("Nothing to seal");
      audit(1);
      new WormAuditChainer(config).chainOnce(NOW);
      review.runOnePage(input, output);
      assertThat(review.getProcessSummary(output, false).toString()).contains("1 chain links will be sealed", "1 checkpoints");
      assertThat(STORE.all(WormAuditTables.EXPORT)).isEmpty();
      var load = new ExportProcesses.ExportLoad(storage);
      assertThat(load.getProcessSummary(output, true)).isEmpty();
      load.runOnePage(input, output);
      load.postRun(new BackendStepPostRunInput(input), new BackendStepPostRunOutput(output));
      assertThat(load.getProcessSummary(output, true).toString()).contains("1 links sealed in export");
      var rows = STORE.all(WormAuditTables.EXPORT);
      var verifyInput = new RunBackendStepInput().withRecords(rows).addValue("recordIds", rows.getFirst().getValueString("id"));
      assertThat(new ExportProcesses.VerifyExtract().getQueryFilter(verifyInput).getCriteria()).isNotEmpty();
      var verifyReview = new ExportProcesses.VerifyReview();
      verifyReview.runOnePage(verifyInput, output);
      assertThat(verifyReview.getProcessSummary(output, false).toString()).contains("1 sealed exports");
      var verifyLoad = new ExportProcesses.VerifyLoad(storage);
      verifyLoad.runOnePage(verifyInput, output);
      assertThat(verifyLoad.getProcessSummary(output, true).toString()).contains("1 links verified");
      new ExportProcesses.Daily().run(input, output);
      assertThat(output.getValueString("outcome")).isEqualTo("PASS");
      audit(2);
      new WormAuditChainer(config).chainOnce(NOW);
      new ExportProcesses.Daily().run(input, output);
      assertThat(output.getValueString("outcome")).isEqualTo("FAIL");
      assertThat(ProcessesAndAlertsTest.Sink.beats).contains("wormaudit.export.daily");
      new ExportProcesses.ExportLoad();
      new ExportProcesses.VerifyLoad();
   }


   /*******************************************************************************
    ** Exercise malformedJsonIsValueFreeAndConfigRejectsUnsafePrefixes.
    *******************************************************************************/
   @Test
   void malformedJsonIsValueFreeAndConfigRejectsUnsafePrefixes() throws Exception
   {
      assertThatThrownBy(() -> ExportFiles.parse("{\"x\":\"CANARY\",\"x\":2}".getBytes(StandardCharsets.UTF_8)))
         .hasMessage("Invalid sealed JSON").hasNoCause();
      assertThatThrownBy(() -> config.withExportPrefix("../escape").validate()).isInstanceOf(IllegalArgumentException.class);
      config.withExportPrefix("evidence/audit").withExportBucketAlias("backup").withExportCron("0 5 2 * * ?").validate();
      assertThat(config.getExportBucketAlias()).isEqualTo("backup");
      try(var files = new ExportFiles())
      {
         assertThatThrownBy(() -> files.file("../escape")).isInstanceOf(IllegalArgumentException.class);
      }
   }


   /*******************************************************************************
    ** Re-hash a tampered object and catalog to reach the independent signature checks.
    *******************************************************************************/
   QRecord rewrite(QRecord row, String name, byte[] bytes) throws Exception
   {
      String prefix = row.getValueString("object_prefix");
      storage.objects.put(prefix + name, bytes);
      Map<String, Object> manifest = ExportFiles.parse(storage.objects.get(prefix + "manifest.json"));
      Map<String, Object> hashes = new LinkedHashMap<>((Map<String, Object>) manifest.get("files"));
      hashes.put(name, java.util.HexFormat.of().formatHex(Hashes.digest(bytes)));
      manifest.put("files", hashes);
      byte[] encoded = Jcs.bytes(manifest);
      storage.objects.put(prefix + "manifest.json", encoded);
      tamper(WormAuditTables.EXPORT, row.getValueLong("id"), "manifest_sha256", java.util.HexFormat.of().formatHex(Hashes.digest(encoded)));
      return (STORE.get(WormAuditTables.EXPORT, row.getValueLong("id")));
   }


   /*******************************************************************************
    ** Exercise independentSignaturesMerkleAndSealedContentChecks.
    *******************************************************************************/
   @Test
   void independentSignaturesMerkleAndSealedContentChecks() throws Exception
   {
      audit(1);
      QRecord row = seal();
      String prefix = row.getValueString("object_prefix");
      byte[] originalCheckpoint = storage.objects.get(prefix + "checkpoints.jsonl");
      Map<String, Object> checkpoint = ExportFiles.parse(originalCheckpoint);
      checkpoint.put("signature", java.util.Base64.getEncoder().encodeToString(new byte[64]));
      row = rewrite(row, "checkpoints.jsonl", (Jcs.string(checkpoint) + "\n").getBytes(StandardCharsets.UTF_8));
      assertThat(findings(row)).contains("checkpoint 1: signature does not verify");
      checkpoint = ExportFiles.parse(originalCheckpoint);
      checkpoint.put("merkle_root", "a".repeat(64));
      row = rewrite(row, "checkpoints.jsonl", (Jcs.string(checkpoint) + "\n").getBytes(StandardCharsets.UTF_8));
      assertThat(findings(row)).contains("Merkle root or head hash differs");
      row = rewrite(row, "checkpoints.jsonl", originalCheckpoint);
      Map<String, Object> document = ExportFiles.parse(storage.objects.get(prefix + "links.jsonl"));
      Map<String, Object> content = (Map<String, Object>) document.get("content");
      ((Map<String, Object>) content.get("audit")).put("message", "CANARY-SEALED");
      row = rewrite(row, "links.jsonl", (Jcs.string(document) + "\n").getBytes(StandardCharsets.UTF_8));
      assertThat(findings(row)).contains("sealed content differs from the chained hash").doesNotContain("CANARY");
      storage.objects.remove(prefix + "links.jsonl");
      assertThat(findings(row)).contains("cannot be read or has invalid structure").doesNotContain("CANARY");
   }


   /*******************************************************************************
    ** Exercise concurrentExportersDoNotOverlapAndMultipleSelectionsPersistSeparately.
    *******************************************************************************/
   @Test
   void concurrentExportersDoNotOverlapAndMultipleSelectionsPersistSeparately() throws Exception
   {
      audit(1);
      new WormAuditChainer(config).chainOnce(NOW);
      var instance = com.kingsrook.qqq.backend.core.context.QContext.getQInstance();
      var workers = java.util.concurrent.Executors.newFixedThreadPool(2);
      try
      {
         var jobs = new java.util.ArrayList<java.util.concurrent.Future<SealedExporter.Result>>();
         for(int i = 0; i < 2; i++)
         {
            jobs.add(workers.submit(() ->
            {
               com.kingsrook.qqq.backend.core.context.QContext.init(instance, new com.kingsrook.qqq.backend.core.model.session.QSession());
               try
               {
                  return (new SealedExporter(config, storage).run("USER", NOW));
               }
               finally
               {
                  com.kingsrook.qqq.backend.core.context.QContext.clear();
               }
            }));
         }
         int sealed = 0;
         for(var job : jobs)
         {
            var result = job.get(10, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(result.failed()).as(result.message()).isFalse();
            sealed += result.row() == null ? 0 : 1;
         }
         assertThat(sealed).isEqualTo(1);
      }
      finally
      {
         workers.shutdownNow();
      }
      audit(2);
      seal();
      var load = new ExportProcesses.VerifyLoad(storage);
      load.runOnePage(new RunBackendStepInput().withRecords(STORE.all(WormAuditTables.EXPORT)), new RunBackendStepOutput());
      assertThat(STORE.all(WormAuditTables.VERIFICATION)).hasSize(2)
         .allMatch(r -> "PASS".equals(r.getValueString("outcome")));
      assertThat(STORE.all(WormAuditTables.VERIFICATION)).extracting(r -> r.getValueLong("export_id")).doesNotHaveDuplicates();
   }


   /*******************************************************************************
    ** Exercise h2TransactionRoundTripAndFailedPutHasNoCatalogRow.
    *******************************************************************************/
   @Test
   void h2TransactionRoundTripAndFailedPutHasNoCatalogRow() throws Exception
   {
      String url = "jdbc:h2:mem:exports_" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = java.sql.DriverManager.getConnection(url, "sa", ""))
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         com.kingsrook.qqq.backend.core.context.QContext.init(instance, new com.kingsrook.qqq.backend.core.model.session.QSession());
         WormAuditTestSupport.lookups();
         audit(1);
         detail(1, 1);
         QRecord row = seal();
         assertThat(verify(row).result().passed()).isTrue();
         assertThat(verify(STORE.get(WormAuditTables.EXPORT, row.getValueLong("id"))).result().passed()).isTrue();
         connection.createStatement().execute("UPDATE audit_detail SET new_value='changed' WHERE id=1");
         assertThat(findings(row)).contains("link 1 (audit 1): live content differs");
         audit(2);
         new WormAuditChainer(config).chainOnce(NOW);
         storage.failPut = storage.objects.size() + 1;
         assertThat(new SealedExporter(config, storage).run("USER", NOW).failed()).isTrue();
         assertThat(STORE.all(WormAuditTables.EXPORT)).hasSize(1);
      }
   }


   /*******************************************************************************
    ** Exercise realAdapterRequiresBackupRoleAndPositiveCapability.
    *******************************************************************************/
   @Test
   void realAdapterRequiresBackupRoleAndPositiveCapability() throws Exception
   {
      var bucket = new com.kingsrook.qbits.objectstorage.config.StorageBucketConfig("worm_audit")
         .withConnection("test").withBucketName("test-bucket").withIndexed(false)
         .withRole(com.kingsrook.qbits.objectstorage.config.BucketRole.BACKUP);
      System.setProperty("worm.unit.access", "unit-access");
      System.setProperty("worm.unit.secret", "unit-secret");
      var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
      var responseVersion = new java.util.concurrent.atomic.AtomicReference<>("sealed-version");
      var requested = new java.util.concurrent.CopyOnWriteArrayList<String>();
      server.createContext("/test-bucket/links.jsonl", exchange ->
      {
         requested.add(exchange.getRequestURI().getRawQuery());
         exchange.getResponseHeaders().add("x-amz-version-id", responseVersion.get());
         byte[] bytes = "sealed fixture".getBytes(StandardCharsets.UTF_8);
         exchange.sendResponseHeaders(200, bytes.length);
         try(var output = exchange.getResponseBody())
         {
            output.write(bytes);
         }
      });
      server.start();
      try
      {
         com.kingsrook.qbits.objectstorage.api.ObjectStorage.configureStandalone(
            new com.kingsrook.qbits.objectstorage.ObjectStorageQBitConfig().withBackendName("memory")
               .withAllowedSecretRefPatterns(List.of("prop.worm.unit.*"))
               .withConnection(new com.kingsrook.qbits.objectstorage.config.StorageConnectionConfig("test")
                  .withEndpoint("http://127.0.0.1:" + server.getAddress().getPort()).withRegion("us-east-1")
                  .withAddressingStyle(com.kingsrook.qbits.objectstorage.config.AddressingStyle.PATH)
                  .withProviderType(com.kingsrook.qbits.objectstorage.config.ProviderType.MINIO)
                  .withAccessKeyRef("${prop.worm.unit.access}").withSecretKeyRef("${prop.worm.unit.secret}"))
               .withBucket(bucket));
         var adapter = new com.kingsrook.qbits.wormaudit.export.ObjectStorageSealedStore("worm_audit", "unit");
         assertThat(adapter.supportsLock()).isFalse();
         com.kingsrook.qbits.objectstorage.internal.CapabilityStore.record(bucket,
            com.kingsrook.qbits.objectstorage.api.Capability.OBJECT_LOCK,
            com.kingsrook.qbits.objectstorage.api.CapabilityStatus.SUPPORTED, "unit fixture");
         assertThat(adapter.supportsLock()).isTrue();
         try(var input = adapter.getVersion("links.jsonl", "sealed-version"))
         {
            assertThat(new String(input.readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("sealed fixture");
         }
         responseVersion.set("different-version");
         assertThatThrownBy(() -> adapter.getVersion("links.jsonl", "sealed-version"))
            .hasMessage("Storage returned a different object version");
         assertThatThrownBy(() -> adapter.getVersion("links.jsonl", null)).hasMessage("Missing sealed object version");
         assertThat(requested).containsExactly("versionId=sealed-version", "versionId=sealed-version");
         bucket.withRole(com.kingsrook.qbits.objectstorage.config.BucketRole.PRIVATE);
         assertThat(adapter.supportsLock()).isFalse();
      }
      finally
      {
         server.stop(0);
         com.kingsrook.qbits.objectstorage.internal.ObjectStorageRuntime.reset();
         System.clearProperty("worm.unit.access");
         System.clearProperty("worm.unit.secret");
      }
   }
}

