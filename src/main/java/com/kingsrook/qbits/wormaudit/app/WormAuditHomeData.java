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

package com.kingsrook.qbits.wormaudit.app;


import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.objectstorage.api.CapabilityStatus;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.export.ObjectStorageSealedStore;
import com.kingsrook.qbits.wormaudit.export.SealedStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
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
 ** Read-only home snapshot. No audit messages, detail values or canonical content
 ** enter this model. Unexported suffixes are lag; holes before the sealed head
 ** are gaps. Only a later full scheduled chain PASS clears an open chain break.
 *******************************************************************************/
public record WormAuditHomeData(long links, Instant lastLinkAt, long backlog, long settling, int settleSeconds,
   QRecord lastVerification, QRecord openBreak, QRecord lastExport, long exportLag, Long exportAgeHours,
   List<String> exportGaps, String bucketAlias, String lockCapability, String lockReason,
   int retentionYears, QRecord anchor, Instant oldestAudit, Instant nextPurge,
   List<QRecord> recentPurges, List<String> warnings)
{
   /*******************************************************************************
    ** Load using the current instance's configuration and production clock.
    *******************************************************************************/
   public static WormAuditHomeData load() throws QException
   {
      return (load(VerificationRuns.config(), null, Instant.now()));
   }


   /*******************************************************************************
    ** The storage and time seams also serve the memory demo and deterministic tests.
    *******************************************************************************/
   public static WormAuditHomeData load(WormAuditQBitConfig config, SealedStore storage, Instant now) throws QException
   {
      List<String> warnings = new ArrayList<>();
      String capability = "UNKNOWN";
      String reason = "Object Lock capability could not be confirmed";
      try
      {
         SealedStore resolved = storage != null ? storage : config.getSealedStoreSupplier() == null
            ? new ObjectStorageSealedStore(config.getExportBucketAlias(), "home") : config.getSealedStoreSupplier().get();
         CapabilityStatus status = resolved.lockCapability();
         if(status == CapabilityStatus.SUPPORTED || status == CapabilityStatus.UNSUPPORTED)
         {
            capability = status.name();
            reason = status == CapabilityStatus.SUPPORTED ? null : "Export bucket does not support Object Lock";
         }
      }
      catch(Exception e)
      {
         // Provider exception messages can contain credentials or object content.
         reason = "Object Lock capability check failed";
      }
      if(reason != null)
      {
         warnings.add(reason);
      }
      if(config.getSigningKey() == null)
      {
         warnings.add("No signing key configured");
      }
      if(config.getTrustedPublicKeys() == null || config.getTrustedPublicKeys().isEmpty())
      {
         warnings.add("No trusted public keys configured");
      }
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new QueryInput(WormAuditTables.CHAIN)))
      {
         try
         {
            if(transaction instanceof RDBMSTransaction rdbms)
            {
               rdbms.getConnection().setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            }
            AuditStore store = new AuditStore(transaction);
            QRecord lastLink = store.last(WormAuditTables.CHAIN);
            long links = store.count(WormAuditTables.CHAIN, new QQueryFilter());
            Instant cutoff = now.minusSeconds(config.getSettleHorizonSeconds());
            long backlog = store.unchainedCount(cutoff, true);
            long settling = store.unchainedCount(cutoff, false);
            QRecord verification = latest(store, WormAuditTables.VERIFICATION, new QQueryFilter(), "finished_at");
            QQueryFilter dailyFilter = new QQueryFilter(new QFilterCriteria("kind", QCriteriaOperator.EQUALS, "CHAIN"),
               new QFilterCriteria("trigger", QCriteriaOperator.EQUALS, "SCHEDULE"));
            QRecord daily = latest(store, WormAuditTables.VERIFICATION, dailyFilter, "finished_at");
            if(daily == null || daily.getValueInstant("finished_at") == null)
            {
               warnings.add("Daily verification has never run");
            }
            else if(daily.getValueInstant("finished_at").isBefore(now.minus(Duration.ofHours(26))))
            {
               warnings.add("Daily verification last ran more than 26 hours ago");
            }
            QRecord failure = latest(store, WormAuditTables.VERIFICATION, new QQueryFilter(
               new QFilterCriteria("kind", QCriteriaOperator.EQUALS, "CHAIN"), new QFilterCriteria("outcome", QCriteriaOperator.EQUALS, "FAIL")), "id");
            QRecord fullPass = latest(store, WormAuditTables.VERIFICATION, new QQueryFilter(
               new QFilterCriteria("kind", QCriteriaOperator.EQUALS, "CHAIN"), new QFilterCriteria("trigger", QCriteriaOperator.EQUALS, "SCHEDULE"),
               new QFilterCriteria("outcome", QCriteriaOperator.EQUALS, "PASS")), "id");
            QRecord openBreak = failure != null && (fullPass == null || failure.getValueLong("id") > fullPass.getValueLong("id")) ? failure : null;
            QRecord export = store.last(WormAuditTables.EXPORT);
            QRecord anchor = store.anchor();
            long anchorId = anchor.getValueLong("anchor_link_id");
            long exported = export == null ? anchorId : export.getValueLong("to_link_id");
            long lag = store.count(WormAuditTables.CHAIN, new QQueryFilter(new QFilterCriteria("id", QCriteriaOperator.GREATER_THAN, exported)));
            List<String> gaps = gaps(store, anchorId);
            List<QRecord> oldest = store.summary("audit", new QQueryFilter().withOrderBy(new QFilterOrderBy("timestamp", true)).withLimit(1), Set.of("timestamp"));
            Instant oldestAt = oldest.isEmpty() ? null : oldest.getFirst().getValueInstant("timestamp");
            List<QRecord> purges = store.query(WormAuditTables.PURGE, new QQueryFilter()
               .withOrderBy(new QFilterOrderBy("requested_at", false)).withOrderBy(new QFilterOrderBy("id", false)).withLimit(10));
            warnings.addAll(PostgresSetupWarnings.load(transaction, config));
            transaction.commit();
            return (new WormAuditHomeData(links, lastLink == null ? null : lastLink.getValueInstant("chained_at"), backlog, settling,
               config.getSettleHorizonSeconds(), verification, openBreak, export, lag,
               export == null || export.getValueInstant("sealed_at") == null ? null : Math.max(0, Duration.between(export.getValueInstant("sealed_at"), now).toHours()),
               List.copyOf(gaps), config.getExportBucketAlias(), capability, reason, config.getRetentionYears(), anchorId == 0 ? null : anchor,
               oldestAt, oldestAt == null ? null : oldestAt.atZone(ZoneOffset.UTC).plusYears(config.getRetentionYears()).toInstant(), List.copyOf(purges), List.copyOf(warnings)));
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (new QException("Cannot load WORM audit home summary"));
         }
      }
   }


   /*******************************************************************************
    ** Read one result, using id to break equal-time ties deterministically.
    *******************************************************************************/
   private static QRecord latest(AuditStore store, String table, QQueryFilter filter, String time) throws QException
   {
      List<QRecord> rows = store.query(table, filter.withOrderBy(new QFilterOrderBy(time, false))
         .withOrderBy(new QFilterOrderBy("id", false)).withLimit(1));
      return (rows.isEmpty() ? null : rows.getFirst());
   }


   /*******************************************************************************
    ** Sweep export intervals in bounded pages; never enumerate links or objects.
    ** The writer appends ranges in id order. Overlapping ranges extend coverage.
    *******************************************************************************/
   private static List<String> gaps(AuditStore store, long anchor) throws QException
   {
      List<String> gaps = new ArrayList<>();
      long next = anchor + 1;
      long cursor = 0;
      while(true)
      {
         List<QRecord> page = store.page(WormAuditTables.EXPORT, cursor, 1000);
         if(page.isEmpty())
         {
            return (gaps);
         }
         for(QRecord export : page)
         {
            long from = export.getValueLong("from_link_id");
            long to = export.getValueLong("to_link_id");
            if(from > next)
            {
               gaps.add(next + "–" + (from - 1));
            }
            next = Math.max(next, to + 1);
         }
         cursor = page.getLast().getValueLong("id");
      }
   }
}
