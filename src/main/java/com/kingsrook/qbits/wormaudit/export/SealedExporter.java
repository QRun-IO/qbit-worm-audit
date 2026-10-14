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


import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.WormAuditQBitProducer;
import com.kingsrook.qbits.wormaudit.canonical.Jcs;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;


/*******************************************************************************
 ** Seal the checkpointed suffix under the chainer/purger lock. Only successful
 ** uploads with verified lock echoes produce an export row.
 *******************************************************************************/
public class SealedExporter
{
   private final WormAuditQBitConfig config;
   private final SealedStore suppliedStorage;

   /*******************************************************************************
    ** A review scope; execution always recomputes it under the writer lock.
    *******************************************************************************/
   public record Scope(long from, long to, long checkpoints, QRecord previous)
   {
      /*******************************************************************************
       ** Number of links, including the empty checkpoint suffix.
       *******************************************************************************/
      public long count()
      {
         return (Math.max(0, to - from + 1));
      }

      /*******************************************************************************
       ** Value-free Review text.
       *******************************************************************************/
      public String review()
      {
         return (count() == 0 ? "Nothing to seal: no new checkpoint" : WormAuditVerifier.number(count())
            + " chain links will be sealed (links " + WormAuditVerifier.number(from) + "–" + WormAuditVerifier.number(to)
            + ", " + WormAuditVerifier.number(checkpoints) + " checkpoints)");
      }
   }

   /*******************************************************************************
    ** A completed, empty, or failed run suitable for a Result line.
    *******************************************************************************/
   public record Result(QRecord row, String message, boolean failed)
   {
   }

   /*******************************************************************************
    ** Production storage is resolved lazily, so an empty run needs no bucket.
    *******************************************************************************/
   public SealedExporter(WormAuditQBitConfig config)
   {
      this(config, null);
   }


   /*******************************************************************************
    ** Inject the tiny storage boundary for deterministic tests.
    *******************************************************************************/
   public SealedExporter(WormAuditQBitConfig config, SealedStore storage)
   {
      this.config = config;
      this.suppliedStorage = storage;
   }


   /*******************************************************************************
    ** Select the contiguous suffix, never silently skipping an unexported purge.
    *******************************************************************************/
   public static Scope scope(AuditStore store) throws QException
   {
      QRecord previous = store.last(WormAuditTables.EXPORT);
      long anchor = store.anchor().getValueLong("anchor_link_id");
      long after = previous == null ? anchor : previous.getValueLong("to_link_id");
      if(after < anchor)
      {
         throw (new QException("Unexported links were purged"));
      }
      QRecord checkpoint = store.last(WormAuditTables.CHECKPOINT);
      long to = checkpoint == null ? after : Math.max(after, checkpoint.getValueLong("to_link_id"));
      long count = 0;
      long cursor = 0;
      while(true)
      {
         List<QRecord> page = checkpoints(store, after + 1, to, cursor);
         if(page.isEmpty())
         {
            break;
         }
         count += page.size();
         cursor = page.getLast().getValueLong("id");
      }
      return (new Scope(after + 1, to, count, previous));
   }


   /*******************************************************************************
    ** Select checkpoint envelopes wholly contained in the export range.
    *******************************************************************************/
   private static List<QRecord> checkpoints(AuditStore store, long from, long to, long after) throws QException
   {
      return (store.query(WormAuditTables.CHECKPOINT, new QQueryFilter(
         new QFilterCriteria("id", QCriteriaOperator.GREATER_THAN, after),
         new QFilterCriteria("from_link_id", QCriteriaOperator.GREATER_THAN_OR_EQUALS, from),
         new QFilterCriteria("to_link_id", QCriteriaOperator.LESS_THAN_OR_EQUALS, to))
         .withOrderBy(new QFilterOrderBy("id", true)).withLimit(1000)));
   }


   /*******************************************************************************
    ** Execute with alerts on user and scheduled failures; schedules always beat.
    *******************************************************************************/
   public Result run(String trigger, Instant now)
   {
      try
      {
         config.validate();
         Result result = lockedRun(now);
         QAlerts.resolve("worm_audit.export.failed", "export", "Sealed audit export completed");
         return (result);
      }
      catch(Exception e)
      {
         // All exposed failures originate here or use a fixed, value-free code.
         String reason = e instanceof ExportFailure ? e.getMessage() : "Sealed export failed: storage or database operation failed";
         QAlerts.raise(new AlertSignal("worm_audit.export.failed").withDedupKey("export").withTitle(reason));
         return (new Result(null, reason, true));
      }
      finally
      {
         if("SCHEDULE".equals(trigger))
         {
            QAlerts.heartbeat("worm_audit.export.daily");
         }
      }
   }


   /*******************************************************************************
    ** Serialize with writers in this JVM and PostgreSQL writers on other hosts.
    *******************************************************************************/
   private Result lockedRun(Instant now) throws Exception
   {
      WormAuditChainer.JVM_LOCK.lock();
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new QueryInput(WormAuditTables.CHAIN)))
      {
         try
         {
            if(transaction instanceof RDBMSTransaction rdbms && "PostgreSQL".equals(rdbms.getConnection().getMetaData().getDatabaseProductName()))
            {
               try(Statement statement = rdbms.getConnection().createStatement();
                   ResultSet result = statement.executeQuery("SELECT pg_advisory_xact_lock(" + WormAuditChainer.ADVISORY_LOCK + ")"))
               {
                  result.next();
               }
            }
            AuditStore store = new AuditStore(transaction);
            Scope scope = scope(store);
            Result result;
            if(scope.count() == 0)
            {
               result = new Result(null, scope.review(), false);
            }
            else
            {
               SealedStore storage = suppliedStorage == null
                  ? new ObjectStorageSealedStore(config.getExportBucketAlias(), java.util.UUID.randomUUID().toString()) : suppliedStorage;
               result = seal(store, storage, scope, now.truncatedTo(ChronoUnit.MILLIS));
            }
            transaction.commit();
            return (result);
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (e);
         }
      }
      finally
      {
         WormAuditChainer.JVM_LOCK.unlock();
      }
   }


   /*******************************************************************************
    ** Build locally before uploading. Partial remote uploads have no database row.
    *******************************************************************************/
   private Result seal(AuditStore store, SealedStore storage, Scope scope, Instant now) throws Exception
   {
      if(!storage.supportsLock())
      {
         throw (new ExportFailure("Export refused: bucket does not support Object Lock"));
      }
      Instant until = now.atZone(ZoneOffset.UTC).plusYears(config.getRetentionYears()).toInstant();
      String prefix = config.getExportPrefix() + "/" + DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC).format(now)
         + "/" + scope.from() + "-" + scope.to() + "/";
      QRecord row;
      try(ExportFiles files = new ExportFiles())
      {
         String head = writeLinks(files, store, scope);
         long[] checkpointIds = writeCheckpoints(files, store, scope);
         Map<String, Object> manifest = new LinkedHashMap<>();
         manifest.put("format", "worm-audit-export/1");
         manifest.put("fromLinkId", scope.from());
         manifest.put("toLinkId", scope.to());
         manifest.put("linkCount", scope.count());
         manifest.put("checkpointCount", scope.checkpoints());
         manifest.put("files", Map.of("links.jsonl", ExportFiles.sha256(files.file("links.jsonl")),
            "checkpoints.jsonl", ExportFiles.sha256(files.file("checkpoints.jsonl"))));
         manifest.put("headHash", head);
         String previous = scope.previous() == null ? null : scope.previous().getValueString("manifest_sha256");
         manifest.put("prevManifestSha256", previous);
         manifest.put("qbitVersion", WormAuditQBitProducer.VERSION);
         manifest.put("createdAt", now.toString());
         Files.write(files.file("manifest.json"), Jcs.bytes(manifest));
         row = new QRecord().withValue("from_link_id", scope.from()).withValue("to_link_id", scope.to())
            .withValue("from_checkpoint_id", checkpointIds[0]).withValue("to_checkpoint_id", checkpointIds[1])
            .withValue("bucket_alias", config.getExportBucketAlias()).withValue("object_prefix", prefix)
            .withValue("manifest_key", prefix + "manifest.json").withValue("manifest_sha256", ExportFiles.sha256(files.file("manifest.json")))
            .withValue("prev_manifest_sha256", previous).withValue("object_count", 3L)
            .withValue("lock_mode", "COMPLIANCE").withValue("retain_until", until).withValue("sealed_at", now);
         if(!new SealedExportVerifier(config, storage).inspect(files, row, store).result().passed())
         {
            throw (new ExportFailure("Export refused: source does not match the signed chain"));
         }
         long bytes = 0;
         Map<String, String> versions = new LinkedHashMap<>();
         for(String name : ExportFiles.NAMES)
         {
            String version = storage.put(prefix + name, files.file(name), until);
            if(!ExportFiles.validVersion(version))
            {
               throw (new ExportFailure("Export refused: object " + name + " returned no version id"));
            }
            var headObject = storage.head(prefix + name);
            if(!ExportFiles.locked(headObject, until))
            {
               throw (new ExportFailure("Export refused: object " + name + " did not echo COMPLIANCE retention"));
            }
            if(!version.equals(headObject.getVersionId()))
            {
               throw (new ExportFailure("Export refused: object " + name + " version changed after upload"));
            }
            versions.put(name, version);
            bytes += Files.size(files.file(name));
         }
         row.withValue("byte_count", bytes).withValue("object_versions", Jcs.string(versions));
      }
      row = store.insert(WormAuditTables.EXPORT, List.of(row)).getFirst();
      return (new Result(row, WormAuditVerifier.number(scope.count()) + " links sealed in export " + row.getValueLong("id")
         + " (retained until " + until + ")", false));
   }


   /*******************************************************************************
    ** Stream canonical lines in pages of 1000 with batched content lookups.
    *******************************************************************************/
   private String writeLinks(ExportFiles files, AuditStore store, Scope scope) throws Exception
   {
      long cursor = scope.from() - 1;
      String head = null;
      try(BufferedWriter writer = Files.newBufferedWriter(files.file("links.jsonl"), StandardCharsets.UTF_8))
      {
         while(cursor < scope.to())
         {
            List<QRecord> links = store.page(WormAuditTables.CHAIN, cursor, (int) Math.min(1000, scope.to() - cursor));
            if(links.isEmpty())
            {
               throw (new ExportFailure("Export refused: chain range is incomplete"));
            }
            Map<Long, QRecord> audits = AuditStore.index(store.in("audit", "id", links.stream().map(r -> r.getValueLong("audit_id")).toList()));
            Map<Long, QRecord> details = ExportFiles.details(store, links);
            for(QRecord link : links)
            {
               if(link.getValueLong("id") != cursor + 1 || link.getValueLong("id") > scope.to())
               {
                  throw (new ExportFailure("Export refused: chain range is incomplete"));
               }
               byte[] content = store.canonical(audits.get(link.getValueLong("audit_id")), AuditStore.detailIds(link), details);
               if(!Hashes.link(link.getValueString("prev_hash"), content).equals(link.getValueString("link_hash")))
               {
                  throw (new ExportFailure("Export refused: content differs at link " + link.getValueLong("id")));
               }
               writer.write(Jcs.string(Map.of("link", ExportFiles.link(link), "content", ExportFiles.parse(content))));
               writer.write('\n');
               head = link.getValueString("link_hash");
               cursor = link.getValueLong("id");
            }
         }
      }
      return (head);
   }


   /*******************************************************************************
    ** Stream complete signed checkpoint envelopes in keyset pages.
    *******************************************************************************/
   private long[] writeCheckpoints(ExportFiles files, AuditStore store, Scope scope) throws Exception
   {
      long first = 0;
      long cursor = 0;
      try(BufferedWriter writer = Files.newBufferedWriter(files.file("checkpoints.jsonl"), StandardCharsets.UTF_8))
      {
         while(true)
         {
            List<QRecord> page = checkpoints(store, scope.from(), scope.to(), cursor);
            if(page.isEmpty())
            {
               break;
            }
            for(QRecord row : page)
            {
               first = first == 0 ? row.getValueLong("id") : first;
               cursor = row.getValueLong("id");
               writer.write(Jcs.string(ExportFiles.checkpoint(row)));
               writer.write('\n');
            }
         }
      }
      return (new long[] { first, cursor });
   }


   /*******************************************************************************
    ** Only fixed messages constructed here may reach an alert or Result screen.
    *******************************************************************************/
   private static class ExportFailure extends IOException
   {
      /*******************************************************************************
       ** Carry a value-free exporter reason without a provider exception cause.
       *******************************************************************************/
      ExportFailure(String reason)
      {
         super(reason);
      }
   }
}

