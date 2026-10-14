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

package com.kingsrook.qbits.wormaudit.export;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.canonical.Jcs;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.checkpoint.Checkpoints;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qbits.wormaudit.verify.VerificationResult;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;


/*******************************************************************************
 ** Verify the sealed evidence before comparing it to a repeatable live snapshot.
 ** No exported content or provider/parser exception text enters diagnostics.
 *******************************************************************************/
public class SealedExportVerifier
{
   private final WormAuditQBitConfig config;
   private final SealedStore suppliedStorage;

   /*******************************************************************************
    ** Findings plus the number verified without live rows after a retention purge.
    *******************************************************************************/
   public record Report(VerificationResult result, long purged)
   {
   }

   /*******************************************************************************
    ** Production entry point.
    *******************************************************************************/
   public SealedExportVerifier(WormAuditQBitConfig config)
   {
      this(config, null);
   }


   /*******************************************************************************
    ** Testable storage boundary.
    *******************************************************************************/
   public SealedExportVerifier(WormAuditQBitConfig config, SealedStore storage)
   {
      this.config = config;
      this.suppliedStorage = storage;
   }


   /*******************************************************************************
    ** Persist exactly one verification row for this selected export, even on failure.
    *******************************************************************************/
   public Report verify(QRecord export, String trigger) throws QException
   {
      config.effectiveSettings();
      VerificationResult failure = new VerificationResult();
      failure.scope(0, export.getValueLong("from_link_id"), export.getValueLong("to_link_id"));
      Report report;
      WormAuditChainer.JVM_LOCK.lock();
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new QueryInput(WormAuditTables.CHAIN));
          ExportFiles files = new ExportFiles())
      {
         try
         {
            if(transaction instanceof RDBMSTransaction rdbms)
            {
               rdbms.getConnection().setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            }
            SealedStore storage = suppliedStorage == null
               ? config.getSealedStoreSupplier() == null || !config.getExportBucketAlias().equals(export.getValueString("bucket_alias"))
                  ? new ObjectStorageSealedStore(export.getValueString("bucket_alias"), "verify-" + export.getValueLong("id"))
                  : config.getSealedStoreSupplier().get() : suppliedStorage;
            Map<String, Object> versions = ExportFiles.parse(export.getValueString("object_versions").getBytes(StandardCharsets.UTF_8));
            for(String name : ExportFiles.NAMES)
            {
               String key = export.getValueString("object_prefix") + name;
               if(!(versions.get(name) instanceof String version) || !ExportFiles.validVersion(version))
               {
                  failure.add(null, null, "object " + name + " has no recorded sealed version id");
                  throw (new IOException("Missing sealed object version"));
               }
               var head = storage.head(key);
               if(head == null)
               {
                  failure.add(null, null, "object " + key + " is missing" + ("GOVERNANCE".equals(export.getValueString("lock_mode"))
                     ? "; possible GOVERNANCE bypass removal by an administrator" : ""));
               }
               if(head != null && !version.equals(head.getVersionId()))
               {
                  failure.add(null, null, "object " + name + " was overwritten after sealing (current version " + head.getVersionId()
                     + ", sealed version " + version + " is still retained under Object Lock)");
               }
               if(!ExportFiles.locked(head, export.getValueString("lock_mode"), export.getValueInstant("retain_until")))
               {
                  failure.add(null, null, "object " + name + " lacks the recorded " + export.getValueString("lock_mode") + " retention");
               }
            }
            for(String name : ExportFiles.NAMES)
            {
               String key = export.getValueString("object_prefix") + name;
               try(InputStream input = storage.getVersion(key, (String) versions.get(name)))
               {
                  Files.copy(input, files.file(name));
               }
               catch(Exception e)
               {
                  failure.add(null, null, "object " + key + " sealed version cannot be read" + ("GOVERNANCE".equals(export.getValueString("lock_mode"))
                     ? "; if removed, possible GOVERNANCE bypass removal by an administrator" : ""));
                  throw (new IOException("Cannot read sealed object version"));
               }
            }
            report = inspect(files, export, new AuditStore(transaction));
            for(var item : failure.getBreaks())
            {
               report.result().add(item.linkId(), item.auditId(), item.reason());
            }
            transaction.commit();
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (e);
         }
      }
      catch(Exception e)
      {
         failure.add(null, null, "Sealed export cannot be read or has invalid structure");
         report = new Report(failure, 0);
      }
      finally
      {
         WormAuditChainer.JVM_LOCK.unlock();
      }
      VerificationRuns.save(report.result(), trigger, export.getValueLong("id"));
      return (report);
   }


   /*******************************************************************************
    ** Inspect local files, also used by the exporter before committing any objects.
    *******************************************************************************/
   public Report inspect(ExportFiles files, QRecord export, AuditStore store) throws Exception
   {
      VerificationResult result = new VerificationResult();
      long from = export.getValueLong("from_link_id");
      long to = export.getValueLong("to_link_id");
      result.scope(0, from, to);
      if(!Objects.equals(ExportFiles.sha256(files.file("manifest.json")), export.getValueString("manifest_sha256")))
      {
         result.add(null, null, "object manifest.json hash does not match the export row");
         return (new Report(result, 0));
      }
      if(Files.size(files.file("manifest.json")) > 65536)
      {
         result.add(null, null, "Manifest exceeds the format size limit");
         return (new Report(result, 0));
      }
      Map<String, Object> manifest = ExportFiles.parse(Files.readAllBytes(files.file("manifest.json")));
      if(!"worm-audit-export/1".equals(manifest.get("format")) || from < 1 || to < from
         || !Objects.equals(manifest.get("fromLinkId"), from) || !Objects.equals(manifest.get("toLinkId"), to)
         || !Objects.equals(manifest.get("linkCount"), to - from + 1)
         || !Objects.equals(manifest.get("createdAt"), export.getValueInstant("sealed_at").toString())
         || !java.util.Set.of("GOVERNANCE", "COMPLIANCE").contains(export.getValueString("lock_mode"))
         || !Objects.equals(export.getValueString("manifest_key"), export.getValueString("object_prefix") + "manifest.json"))
      {
         result.add(null, null, "Manifest metadata does not match the export row");
      }
      QQueryFilter previousFilter = new QQueryFilter().withOrderBy(new QFilterOrderBy("id", false)).withLimit(1);
      if(export.getValueLong("id") != null)
      {
         previousFilter.withCriteria(new QFilterCriteria("id", QCriteriaOperator.LESS_THAN, export.getValueLong("id")));
      }
      List<QRecord> previousRows = store.query(WormAuditTables.EXPORT, previousFilter);
      QRecord previous = previousRows.isEmpty() ? null : previousRows.getFirst();
      String previousHash = previous == null ? null : previous.getValueString("manifest_sha256");
      if(!Objects.equals(manifest.get("prevManifestSha256"), previousHash)
         || !Objects.equals(export.getValueString("prev_manifest_sha256"), previousHash)
         || (previous != null && previous.getValueLong("to_link_id") != from - 1))
      {
         result.add(null, null, "prevManifestSha256 does not match the previous export row");
      }
      Map<?, ?> hashes = (Map<?, ?>) manifest.get("files");
      for(String name : List.of("links.jsonl", "checkpoints.jsonl"))
      {
         if(!Objects.equals(ExportFiles.sha256(files.file(name)), hashes.get(name)))
         {
            result.add(null, null, "object " + name + " hash does not match the manifest");
         }
      }
      if(!result.passed())
      {
         return (new Report(result, 0));
      }
      return (checkLines(files, export, store, manifest, result));
   }


   /*******************************************************************************
    ** Consume links alongside their checkpoint envelopes. Only one checkpoint's
    ** hashes and one content page are retained, never the whole export.
    *******************************************************************************/
   private Report checkLines(ExportFiles files, QRecord export, AuditStore store, Map<String, Object> manifest, VerificationResult result) throws Exception
   {
      long from = export.getValueLong("from_link_id");
      long to = export.getValueLong("to_link_id");
      long cursor = from - 1;
      long checkpointCount = 0;
      long checked = 0;
      long purged = 0;
      long anchor = store.anchor().getValueLong("anchor_link_id");
      String previousHash = from == 1 ? Hashes.GENESIS : null;
      if(cursor == anchor)
      {
         previousHash = store.anchor().getValueString("anchor_hash");
      }
      long lastCheckpoint = 0;
      try(BufferedReader links = Files.newBufferedReader(files.file("links.jsonl"), StandardCharsets.UTF_8);
          BufferedReader checkpoints = Files.newBufferedReader(files.file("checkpoints.jsonl"), StandardCharsets.UTF_8))
      {
         String line;
         while((line = checkpoints.readLine()) != null)
         {
            QRecord checkpoint = ExportFiles.record(ExportFiles.parse(line.getBytes(StandardCharsets.UTF_8)));
            long checkpointId = checkpoint.getValueLong("id");
            String label = "checkpoint " + WormAuditVerifier.number(checkpointId) + ": ";
            long end = checkpoint.getValueLong("to_link_id");
            long start = checkpoint.getValueLong("from_link_id");
            long count = checkpoint.getValueLong("link_count");
            if(start != cursor + 1 || end < start || end > to || count != end - start + 1
               || count > Integer.MAX_VALUE || checkpointId <= lastCheckpoint)
            {
               result.add(null, null, label + "invalid or incomplete checkpoint range");
               break;
            }
            if(!Checkpoints.verify(checkpoint, config.getTrustedPublicKeys().get(checkpoint.getValueString("key_id"))))
            {
               result.add(null, null, label + "signature does not verify");
            }
            if(checkpointCount == 0 && !Objects.equals(export.getValueLong("from_checkpoint_id"), checkpointId))
            {
               result.add(null, null, label + "first checkpoint does not match the export row");
            }
            List<String> hashes = new ArrayList<>();
            while(cursor < end)
            {
               List<Map<String, Object>> page = new ArrayList<>();
               for(int i = 0, size = (int) Math.min(1000, end - cursor); i < size; i++)
               {
                  String linkLine = links.readLine();
                  if(linkLine == null)
                  {
                     result.add(cursor + 1, null, "Sealed links are missing from the checkpoint range");
                     result.scope(checked, from, to);
                     return (new Report(result, purged));
                  }
                  page.add(ExportFiles.parse(linkLine.getBytes(StandardCharsets.UTF_8)));
               }
               compareLive(page, store, export, anchor, result);
               for(Map<String, Object> document : page)
               {
                  Map<?, ?> link = (Map<?, ?>) document.get("link");
                  long id = (Long) link.get("id");
                  long auditId = (Long) link.get("auditId");
                  String prefix = "link " + WormAuditVerifier.number(id) + " (audit " + WormAuditVerifier.number(auditId) + "): ";
                  String prev = (String) link.get("prevHash");
                  String hash = (String) link.get("linkHash");
                  if(id != cursor + 1 || (previousHash != null && !Objects.equals(prev, previousHash)))
                  {
                     result.add(id, auditId, prefix + "sealed chain continuity differs");
                  }
                  Map<?, ?> content = (Map<?, ?>) document.get("content");
                  Map<?, ?> audit = (Map<?, ?>) content.get("audit");
                  List<?> detailIds = (List<?>) link.get("detailIds");
                  List<?> details = (List<?>) content.get("details");
                  List<?> contentIds = details.stream().map(d -> ((Map<?, ?>) d).get("id")).toList();
                  if(!Objects.equals(audit.get("id"), auditId) || !Objects.equals(content.get("v"), 1L)
                     || !List.of("AUDIT", "LATE_DETAIL").contains(link.get("kind"))
                     || detailIds.size() > 250 || !detailIds.equals(contentIds)
                     || detailIds.stream().distinct().count() != detailIds.size()
                     || ("LATE_DETAIL".equals(link.get("kind")) && detailIds.isEmpty()))
                  {
                     result.add(id, auditId, prefix + "sealed content identifiers or coverage differ");
                  }
                  if(!Hashes.link(prev, Jcs.bytes(content)).equals(hash))
                  {
                     result.add(id, auditId, prefix + "sealed content differs from the chained hash");
                  }
                  hashes.add(hash);
                  previousHash = hash;
                  cursor++;
                  checked++;
                  if(id <= anchor)
                  {
                     purged++;
                  }
               }
            }
            if(!Objects.equals(Hashes.merkle(hashes), checkpoint.getValueString("merkle_root"))
               || !Objects.equals(previousHash, checkpoint.getValueString("head_hash")))
            {
               result.add(null, null, label + "Merkle root or head hash differs");
            }
            lastCheckpoint = checkpointId;
            checkpointCount++;
         }
         if(cursor != to || links.readLine() != null || !Objects.equals(manifest.get("checkpointCount"), checkpointCount)
            || !Objects.equals(export.getValueLong("to_checkpoint_id"), lastCheckpoint)
            || !Objects.equals(manifest.get("headHash"), previousHash))
         {
            result.add(null, null, "Sealed range, counts or head hash differ from the manifest");
         }
      }
      result.scope(checked, from, to);
      return (new Report(result, purged));
   }


   /*******************************************************************************
    ** Compare a bounded page by exported ids, so missing live rows cannot vanish
    ** from the verification scope. Purged ids are checked from signed copies only.
    *******************************************************************************/
   private void compareLive(List<Map<String, Object>> page, AuditStore store, QRecord export, long anchor, VerificationResult result) throws Exception
   {
      List<QRecord> sealed = page.stream().map(document ->
      {
         Map<?, ?> link = (Map<?, ?>) document.get("link");
         List<?> ids = (List<?>) link.get("detailIds");
         return (new QRecord().withValue("id", (Long) link.get("id")).withValue("audit_id", (Long) link.get("auditId"))
            .withValue("kind", (String) link.get("kind")).withValue("prev_hash", (String) link.get("prevHash"))
            .withValue("link_hash", (String) link.get("linkHash"))
            .withValue("detail_ids", ids.stream().map(Object::toString).collect(java.util.stream.Collectors.joining(","))));
      }).toList();
      List<QRecord> liveScope = sealed.stream().filter(r -> r.getValueLong("id") > anchor).toList();
      Map<Long, QRecord> live = AuditStore.index(store.in(WormAuditTables.CHAIN, "id", liveScope.stream().map(r -> r.getValueLong("id")).toList()));
      Map<Long, QRecord> audits = AuditStore.index(store.in("audit", "id", liveScope.stream().map(r -> r.getValueLong("audit_id")).toList()));
      Map<Long, QRecord> details = ExportFiles.details(store, liveScope);
      for(int i = 0; i < sealed.size(); i++)
      {
         QRecord link = sealed.get(i);
         long id = link.getValueLong("id");
         long auditId = link.getValueLong("audit_id");
         if(id <= anchor)
         {
            continue;
         }
         String prefix = "link " + WormAuditVerifier.number(id) + " (audit " + WormAuditVerifier.number(auditId) + "): ";
         QRecord current = live.get(id);
         if(current == null)
         {
            result.add(id, auditId, "link " + WormAuditVerifier.number(id) + " is missing from the live chain");
         }
         else
         {
            for(String field : List.of("kind", "audit_id", "detail_ids", "prev_hash", "link_hash"))
            {
               if(!Objects.equals(link.getValue(field), current.getValue(field)))
               {
                  result.add(id, auditId, prefix + "live chain " + field + " differs from the sealed copy");
               }
            }
         }
         try
         {
            QRecord audit = audits.get(auditId);
            if(audit == null)
            {
               result.add(id, auditId, prefix + "live audit header is missing");
            }
            else if(!Arrays.equals(store.canonical(audit, AuditStore.detailIds(link), details), Jcs.bytes(page.get(i).get("content"))))
            {
               result.add(id, auditId, prefix + "live content differs from the sealed copy (sealed "
                  + export.getValueInstant("sealed_at").atZone(ZoneOffset.UTC).toLocalDate() + ")");
            }
         }
         catch(Exception e)
         {
            result.add(id, auditId, prefix + "live content is missing or invalid");
         }
      }
   }
}

