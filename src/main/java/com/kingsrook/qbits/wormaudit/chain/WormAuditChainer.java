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

package com.kingsrook.qbits.wormaudit.chain;


import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.WormAuditSettings;
import com.kingsrook.qbits.wormaudit.checkpoint.Checkpoints;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;


/*******************************************************************************
 ** Single asynchronous writer. PostgreSQL uses a transaction-scoped advisory
 ** lock shared with the retention function. Other backends use a JVM-wide lock:
 ** those deployments must run their chainer in one JVM only.
 *******************************************************************************/
public class WormAuditChainer
{
   public static final long ADVISORY_LOCK = 86753090421L;
   public static final ReentrantLock JVM_LOCK = new ReentrantLock();
   private final WormAuditQBitConfig config;

   /*******************************************************************************
    ** Counts describe committed work; a contended writer tick is skipped.
    *******************************************************************************/
   public record Counts(int audits, int lateDetails, int links, int checkpoints, boolean skipped)
   {
   }

   /*******************************************************************************
    ** Bind host configuration.
    *******************************************************************************/
   public WormAuditChainer(WormAuditQBitConfig config)
   {
      this.config = config;
   }


   /*******************************************************************************
    ** Run a writer tick under one transaction; link ids cannot gap on rollback.
    *******************************************************************************/
   public Counts chainOnce() throws QException
   {
      return (chainOnce(Instant.now()));
   }


   /*******************************************************************************
    ** Clock-injected tick for deterministic settling and checkpoint tests.
    *******************************************************************************/
   public Counts chainOnce(Instant now) throws QException
   {
      config.validate();
      JVM_LOCK.lock();
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new QueryInput(WormAuditTables.CHAIN)))
      {
         try
         {
            if(transaction instanceof RDBMSTransaction rdbms && "PostgreSQL".equals(rdbms.getConnection().getMetaData().getDatabaseProductName()))
            {
               try(Statement statement = rdbms.getConnection().createStatement(); ResultSet result = statement.executeQuery("SELECT pg_try_advisory_xact_lock(" + ADVISORY_LOCK + ")"))
               {
                  result.next();
                  if(!result.getBoolean(1))
                  {
                     return (new Counts(0, 0, 0, 0, true));
                  }
               }
            }
            Counts counts = append(new AuditStore(transaction), now, config.effectiveSettings());
            transaction.commit();
            return (counts);
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (AppendOnlyGuard.map(e));
         }
      }
      finally
      {
         JVM_LOCK.unlock();
      }
   }


   /*******************************************************************************
    ** Append settled headers and uncovered detail chunks, then checkpoint.
    *******************************************************************************/
   private Counts append(AuditStore store, Instant now, WormAuditSettings.Values settings) throws Exception
   {
      QRecord tail = store.last(WormAuditTables.CHAIN);
      QRecord anchor = store.anchor();
      long nextId = tail == null ? anchor.getValueLong("anchor_link_id") + 1 : tail.getValueLong("id") + 1;
      String previous = tail == null ? anchor.getValueString("anchor_hash") : tail.getValueString("link_hash");
      List<QRecord> appended = new ArrayList<>();
      Instant cutoff = now.minusSeconds(settings.settle_horizon_seconds());
      SweepFloors floors = SweepFloors.of(config);
      SweepFloors.Observation observed = store.isRdbms() ? floors.observe(now, store.maxId("audit"), store.maxId("auditDetail")) : null;
      boolean full = floors.fullSweepDue(now);
      List<QRecord> audits = store.unchained(cutoff, config.getBatchSize(), full ? 0L : floors.audit());
      Map<Long, QRecord> details = AuditStore.index(store.in("auditDetail", "auditId", audits.stream().map(r -> r.getValueLong("id")).toList()));
      Map<Long, List<QRecord>> grouped = details.values().stream().collect(Collectors.groupingBy(r -> r.getValueLong("auditId")));
      int lateDetails = 0;
      for(QRecord audit : audits)
      {
         List<Long> ids = grouped.getOrDefault(audit.getValueLong("id"), List.of()).stream().map(r -> r.getValueLong("id")).sorted().toList();
         for(int start = 0; start == 0 || start < ids.size(); start += 250)
         {
            List<Long> chunk = ids.subList(start, Math.min(start + 250, ids.size()));
            QRecord link = link(store, nextId++, start == 0 ? "AUDIT" : "LATE_DETAIL", audit, chunk, details, previous, now);
            appended.add(link);
            previous = link.getValueString("link_hash");
            if(start > 0)
            {
               lateDetails += chunk.size();
            }
         }
      }
      insertLinks(store, appended);
      int linkCount = appended.size();
      appended.clear();
      details = AuditStore.index(store.lateDetails(cutoff, settings.late_detail_lookback_hours(), config.getBatchSize(), full ? 0L : floors.detail()));
      grouped = details.values().stream().collect(Collectors.groupingBy(r -> r.getValueLong("auditId"), TreeMap::new, Collectors.toList()));
      Map<Long, QRecord> headers = AuditStore.index(store.in("audit", "id", grouped.keySet()));
      for(var entry : grouped.entrySet())
      {
         List<Long> ids = entry.getValue().stream().map(r -> r.getValueLong("id")).sorted().toList();
         for(int start = 0; start < ids.size(); start += 250)
         {
            List<Long> chunk = ids.subList(start, Math.min(start + 250, ids.size()));
            QRecord link = link(store, nextId++, "LATE_DETAIL", headers.get(entry.getKey()), chunk, details, previous, now);
            appended.add(link);
            previous = link.getValueString("link_hash");
            lateDetails += chunk.size();
         }
      }
      insertLinks(store, appended);
      if(observed != null)
      {
         floors.swept(observed, now.minusSeconds(settings.settle_horizon_seconds()).minus(SweepFloors.MARGIN),
            audits.size() < config.getBatchSize(), details.size() < config.getBatchSize(), full ? now : null);
      }
      return (new Counts(audits.size(), lateDetails, linkCount + appended.size(), checkpoint(store, now, settings), false));
   }


   /*******************************************************************************
    ** Persist bounded insert batches inside the writer transaction. PostgreSQL's
    ** chain trigger writes the detail coverage rows; elsewhere the writer does,
    ** in the same transaction, so coverage never diverges from the chain.
    *******************************************************************************/
   private void insertLinks(AuditStore store, List<QRecord> links) throws QException
   {
      for(int start = 0; start < links.size(); start += config.getBatchSize())
      {
         store.insert(WormAuditTables.CHAIN, links.subList(start, Math.min(start + config.getBatchSize(), links.size())));
      }
      if(!store.isPostgres())
      {
         List<QRecord> coverage = new ArrayList<>();
         for(QRecord link : links)
         {
            AuditStore.detailIds(link).forEach(id -> coverage.add(new QRecord().withValue("detail_id", id).withValue("chain_id", link.getValueLong("id"))));
         }
         for(int start = 0; start < coverage.size(); start += config.getBatchSize())
         {
            store.insert(WormAuditTables.CHAIN_DETAIL, coverage.subList(start, Math.min(start + config.getBatchSize(), coverage.size())));
         }
      }
   }


   /*******************************************************************************
    ** Build one immutable link from live stored content.
    *******************************************************************************/
   private QRecord link(AuditStore store, long id, String kind, QRecord audit, List<Long> details, Map<Long, QRecord> rows, String previous, Instant now) throws QException
   {
      return (new QRecord().withValue("id", id).withValue("kind", kind).withValue("audit_id", audit.getValueLong("id"))
         .withValue("detail_ids", details.stream().map(Object::toString).collect(Collectors.joining(",")))
         .withValue("prev_hash", previous).withValue("link_hash", Hashes.link(previous, store.canonical(audit, details, rows))).withValue("chained_at", now));
   }


   /*******************************************************************************
    ** Checkpoint the uncheckpointed suffix by count or elapsed time.
    *******************************************************************************/
   private int checkpoint(AuditStore store, Instant now, WormAuditSettings.Values settings) throws Exception
   {
      if(config.getSigningKey() == null)
      {
         return (0);
      }
      QRecord latest = store.last(WormAuditTables.CHECKPOINT);
      long lastId = latest == null ? store.anchor().getValueLong("anchor_link_id") : latest.getValueLong("to_link_id");
      int count = 0;
      while(true)
      {
         List<QRecord> pending = store.page(WormAuditTables.CHAIN, lastId, settings.checkpoint_every_links());
         if(pending.isEmpty())
         {
            return (count);
         }
         Instant since = latest == null ? pending.getFirst().getValueInstant("chained_at") : latest.getValueInstant("created_at");
         if(pending.size() < settings.checkpoint_every_links() && now.isBefore(since.plusSeconds(settings.checkpoint_every_minutes() * 60L)))
         {
            return (count);
         }
         latest = store.insert(WormAuditTables.CHECKPOINT, List.of(Checkpoints.sign(pending, config, now))).getFirst();
         lastId = latest.getValueLong("to_link_id");
         count++;
      }
   }
}
