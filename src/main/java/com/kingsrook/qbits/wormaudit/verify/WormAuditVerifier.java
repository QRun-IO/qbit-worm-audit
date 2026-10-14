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

package com.kingsrook.qbits.wormaudit.verify;


import java.sql.Connection;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.checkpoint.Checkpoints;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;


/*******************************************************************************
 ** Snapshot verification of live content, continuity, exact coverage and signed
 ** checkpoints. Selection runs verify predecessor boundaries but deliberately
 ** omit global completeness; full runs begin at the latest retention anchor.
 *******************************************************************************/
public class WormAuditVerifier
{
   public static final int PAGE_SIZE = 1000;
   private final WormAuditQBitConfig config;

   /*******************************************************************************
    ** Bind trust pins and settle horizon.
    *******************************************************************************/
   public WormAuditVerifier(WormAuditQBitConfig config)
   {
      this.config = config;
   }


   /*******************************************************************************
    ** Verify all live links and settled coverage.
    *******************************************************************************/
   public VerificationResult verify() throws QException
   {
      return (verify(null));
   }


   /*******************************************************************************
    ** Null means full verification; an empty set is an empty selection.
    *******************************************************************************/
   public VerificationResult verify(Set<Long> selection) throws QException
   {
      WormAuditChainer.JVM_LOCK.lock();
      try(QBackendTransaction transaction = QBackendTransaction.openFor(new QueryInput(WormAuditTables.CHAIN)))
      {
         try
         {
            if(transaction instanceof RDBMSTransaction rdbms)
            {
               rdbms.getConnection().setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            }
            VerificationResult result = verify(new AuditStore(transaction), selection, Instant.now());
            transaction.commit();
            return (result);
         }
         catch(Exception e)
         {
            transaction.rollback();
            throw (AppendOnlyGuard.map(e));
         }
      }
      finally
      {
         WormAuditChainer.JVM_LOCK.unlock();
      }
   }


   /*******************************************************************************
    ** Verify one consistent storage snapshot.
    *******************************************************************************/
   private VerificationResult verify(AuditStore store, Set<Long> selection, Instant now) throws QException
   {
      VerificationResult result = new VerificationResult();
      if(config.getSigningKey() == null)
      {
         result.warn("no signing key configured");
      }
      QRecord anchor = store.anchor();
      long anchorId = anchor.getValueLong("anchor_link_id");
      long lastId = anchorId;
      String previous = anchor.getValueString("anchor_hash");
      long checked = 0;
      Long first = null;
      Long last = null;
      Set<Long> missing = selection == null ? null : new HashSet<>(selection);
      CheckpointCursor checkpoints = new CheckpointCursor(store, selection, anchor, result);
      while(true)
      {
         List<QRecord> page = store.page(WormAuditTables.CHAIN, lastId, PAGE_SIZE);
         if(page.isEmpty())
         {
            break;
         }
         List<QRecord> selected = page.stream().filter(r -> selection == null || selection.contains(r.getValueLong("id"))).toList();
         Map<Long, QRecord> headers = AuditStore.index(store.in("audit", "id", selected.stream().map(r -> r.getValueLong("audit_id")).toList()));
         Set<Long> detailIds = new HashSet<>();
         for(QRecord link : selected)
         {
            try
            {
               List<Long> ids = AuditStore.detailIds(link);
               if(ids.size() <= 250)
               {
                  detailIds.addAll(ids);
               }
            }
            catch(IllegalArgumentException e)
            {
               // Content verification reports malformed coverage with its link id.
            }
         }
         Map<Long, QRecord> details = new HashMap<>();
         List<Long> ids = new ArrayList<>(detailIds);
         for(int start = 0; start < ids.size(); start += PAGE_SIZE)
         {
            details.putAll(AuditStore.index(store.in("auditDetail", "id", ids.subList(start, Math.min(start + PAGE_SIZE, ids.size())))));
         }
         for(QRecord link : page)
         {
            long id = link.getValueLong("id");
            long auditId = link.getValueLong("audit_id");
            if(selection == null || selection.contains(id))
            {
               if(missing != null)
               {
                  missing.remove(id);
               }
               checked++;
               first = first == null ? id : first;
               last = id;
               if(selection == null && id != lastId + 1)
               {
                  result.add(id, auditId, "Missing link ids " + number(lastId + 1) + "–" + number(id - 1) + " (gap)");
               }
               if(id != lastId + 1 || previous == null || !previous.equals(link.getValueString("prev_hash")))
               {
                  result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + "): prev-hash discontinuity");
               }
               verifyContent(store, link, headers.get(auditId), details, result);
            }
            previous = link.getValueString("link_hash");
            lastId = id;
         }
         checkpoints.through(lastId);
      }
      checkpoints.through(Long.MAX_VALUE);
      result.scope(checked, first, last);
      if(missing != null)
      {
         missing.stream().sorted().forEach(id -> result.add(id, null, "Missing selected link " + number(id)));
      }
      if(selection == null)
      {
         Instant cutoff = now.minusSeconds(config.getSettleHorizonSeconds());
         if(store.isRdbms())
         {
            store.completeness(cutoff, result);
         }
         else
         {
            completeness(store, store.all(WormAuditTables.CHAIN), cutoff, result);
         }
      }
      return (result);
   }


   /*******************************************************************************
    ** Recompute exact stored content. Diagnostics name covered detail ids because
    ** v1 stores a document hash, not per-field hashes or prior values.
    *******************************************************************************/
   private void verifyContent(AuditStore store, QRecord link, QRecord audit, Map<Long, QRecord> rows, VerificationResult result) throws QException
   {
      long id = link.getValueLong("id");
      long auditId = link.getValueLong("audit_id");
      if(List.of("kind", "detail_ids", "prev_hash", "link_hash", "chained_at").stream().anyMatch(field -> link.getValue(field) == null))
      {
         result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + "): malformed link");
         return;
      }
      if(audit == null)
      {
         result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + "): audit header is missing");
         return;
      }
      if(audit.getValueInstant("timestamp") == null)
      {
         result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + "): missing audit timestamp");
         return;
      }
      try
      {
         List<Long> details = AuditStore.detailIds(link);
         String kind = link.getValueString("kind");
         if(!List.of("AUDIT", "LATE_DETAIL").contains(kind) || details.size() > 250 || ("LATE_DETAIL".equals(kind) && details.isEmpty()))
         {
            result.add(id, auditId, "Break at link " + number(id) + ": invalid kind or detail coverage");
         }
         if(details.size() > 250)
         {
            return;
         }
         Set<Long> unique = new HashSet<>();
         for(long detail : details)
         {
            if(!unique.add(detail))
            {
               result.add(id, auditId, "audit_detail " + number(detail) + " is covered twice or more by the chain");
            }
         }
         String hash = Hashes.link(link.getValueString("prev_hash"), store.canonical(audit, details, rows));
         if(!hash.equals(link.getValueString("link_hash")))
         {
            String table = store.name("auditTable", audit.getValueLong("auditTableId"));
            result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + ", table " + table + ", record "
               + audit.getValueString("recordId") + "): content differs from the chained hash"
               + (details.isEmpty() ? "" : " (audit_detail " + details.stream().map(WormAuditVerifier::number).collect(java.util.stream.Collectors.joining(", ")) + ")"));
         }
      }
      catch(QException | IllegalArgumentException e)
      {
         result.add(id, auditId, "Break at link " + number(id) + " (audit " + number(auditId) + "): " + e.getMessage());
      }
   }


   /*******************************************************************************
    ** Every settled header and detail must occur once; orphan details also fail.
    *******************************************************************************/
   private void completeness(AuditStore store, List<QRecord> links, Instant cutoff, VerificationResult result) throws QException
   {
      Map<Long, Integer> headers = new HashMap<>();
      Map<Long, Integer> details = new HashMap<>();
      for(QRecord link : links)
      {
         if("AUDIT".equals(link.getValueString("kind")))
         {
            headers.merge(link.getValueLong("audit_id"), 1, Integer::sum);
         }
         try
         {
            AuditStore.detailIds(link).forEach(id -> details.merge(id, 1, Integer::sum));
         }
         catch(IllegalArgumentException e)
         {
            // Invalid coverage was already reported while checking link content.
         }
      }
      Map<Long, QRecord> audits = new HashMap<>();
      for(QRecord audit : store.all("audit"))
      {
         long id = audit.getValueLong("id");
         audits.put(id, audit);
         if(audit.getValueInstant("timestamp") == null)
         {
            result.add(null, id, "audit " + number(id) + " has no timestamp");
         }
         else if(audit.getValueInstant("timestamp").isBefore(cutoff))
         {
            coverage("audit", id, headers.getOrDefault(id, 0), result);
         }
      }
      for(QRecord detail : store.all("auditDetail"))
      {
         QRecord audit = audits.get(detail.getValueLong("auditId"));
         if(audit == null || audit.getValueInstant("timestamp") == null || audit.getValueInstant("timestamp").isBefore(cutoff))
         {
            coverage("audit_detail", detail.getValueLong("id"), details.getOrDefault(detail.getValueLong("id"), 0), result);
         }
      }
   }


   /*******************************************************************************
    ** Report coverage without printing any audit content.
    *******************************************************************************/
   private void coverage(String table, long id, int count, VerificationResult result)
   {
      if(count != 1)
      {
         result.add(null, table.equals("audit") ? id : null, table + " " + number(id)
            + (count == 0 ? " is not covered by the chain" : " is covered twice or more by the chain"));
      }
   }


   /*******************************************************************************
    ** Check pinned signatures even for purged ranges. A partially purged range's
    ** Merkle tree requires its sealed export; never claim to recompute it live.
    *******************************************************************************/
   private class CheckpointCursor
   {
      private final AuditStore store;
      private final Set<Long> selection;
      private final QRecord anchor;
      private final VerificationResult result;
      private long after;
      private QRecord next;

      /*******************************************************************************
       ** Keep only one checkpoint pending as pages complete.
       *******************************************************************************/
      CheckpointCursor(AuditStore store, Set<Long> selection, QRecord anchor, VerificationResult result)
      {
         this.store = store;
         this.selection = selection;
         this.anchor = anchor;
         this.result = result;
      }


      /*******************************************************************************
       ** Verify completed ranges, including missing tails at end of the scan.
       *******************************************************************************/
      void through(long lastId) throws QException
      {
         while(true)
         {
            if(next == null)
            {
               List<QRecord> rows = store.page(WormAuditTables.CHECKPOINT, after, 1);
               if(rows.isEmpty())
               {
                  return;
               }
               next = rows.getFirst();
            }
            Long to = next.getValueLong("to_link_id");
            if(to != null && to > lastId)
            {
               return;
            }
            check(next);
            after = next.getValueLong("id");
            next = null;
         }
      }


      /*******************************************************************************
       ** Re-read at most one capped range of hashes in the same snapshot.
       *******************************************************************************/
      private void check(QRecord checkpoint) throws QException
      {
         String prefix = "checkpoint " + number(checkpoint.getValueLong("id")) + ": ";
         if(List.of("from_link_id", "to_link_id", "link_count", "head_hash", "merkle_root", "algorithm", "key_id", "public_key", "signature")
            .stream().anyMatch(field -> checkpoint.getValue(field) == null))
         {
            result.add(null, null, prefix + "malformed checkpoint");
            return;
         }
         long from = checkpoint.getValueLong("from_link_id");
         long to = checkpoint.getValueLong("to_link_id");
         long anchorId = anchor.getValueLong("anchor_link_id");
         if(selection != null && selection.stream().noneMatch(id -> id >= from && id <= to))
         {
            return;
         }
         var pin = config.getTrustedPublicKeys().get(checkpoint.getValueString("key_id"));
         if(pin == null)
         {
            result.add(null, null, prefix + "untrusted key");
         }
         else if(!Checkpoints.verify(checkpoint, pin))
         {
            result.add(null, null, prefix + "signature does not verify");
         }
         if(from < 1 || to < from || checkpoint.getValueLong("link_count") != to - from + 1
            || to - from + 1 > config.getCheckpointEveryLinks())
         {
            result.add(null, null, prefix + "invalid link range or count");
            return;
         }
         if(from <= anchorId)
         {
            QRecord head = to > anchorId ? store.get(WormAuditTables.CHAIN, to) : null;
            if(to > anchorId && (head == null || !Objects.equals(head.getValueString("link_hash"), checkpoint.getValueString("head_hash"))))
            {
               result.add(to, null, prefix + "head mismatch");
            }
            if(to == anchorId && !Objects.equals(anchor.getValueString("anchor_hash"), checkpoint.getValueString("head_hash")))
            {
               result.add(to, null, prefix + "head mismatch with purge anchor");
            }
            result.warn(prefix + "purged range; Merkle proof requires the sealed export");
            return;
         }
         List<String> hashes = new ArrayList<>();
         long cursor = from - 1;
         String head = null;
         while(cursor < to)
         {
            List<QRecord> page = store.page(WormAuditTables.CHAIN, cursor, (int) Math.min(PAGE_SIZE, to - cursor));
            if(page.isEmpty())
            {
               break;
            }
            for(QRecord link : page)
            {
               cursor = link.getValueLong("id");
               if(cursor <= to)
               {
                  hashes.add(link.getValueString("link_hash"));
               }
               if(cursor == to)
               {
                  head = link.getValueString("link_hash");
               }
            }
         }
         if(!Objects.equals(head, checkpoint.getValueString("head_hash")))
         {
            result.add(to, null, prefix + "head mismatch");
         }
         try
         {
            if(hashes.size() != checkpoint.getValueLong("link_count") || hashes.isEmpty()
               || hashes.stream().anyMatch(Objects::isNull) || !Hashes.merkle(hashes).equals(checkpoint.getValueString("merkle_root")))
            {
               result.add(null, null, prefix + "merkle mismatch");
            }
         }
         catch(IllegalArgumentException e)
         {
            result.add(null, null, prefix + "merkle mismatch");
         }
      }
   }


   /*******************************************************************************
    ** Stable human-readable ids matching the process summary contract.
    *******************************************************************************/
   public static String number(long value)
   {
      return (String.format(Locale.US, "%,d", value));
   }
}
