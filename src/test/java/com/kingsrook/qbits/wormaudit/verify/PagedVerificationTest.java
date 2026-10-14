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


import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.canonical.AuditCanonical;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.checkpoint.Checkpoints;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Instrument the storage boundary independently of the memory backend: no
 ** unbounded reads are allowed, including portable completeness checks.
 *******************************************************************************/
class PagedVerificationTest
{
   private static final int LINKS = 25000;
   private static final int PAGE = 137;
   private static final int RANGE = 997;
   private static final Instant NOW = Instant.parse("2026-10-13T00:00:00Z");


   /*******************************************************************************
    ** Cross many non-aligned page/checkpoint boundaries with genuine signatures.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(booleans = { true, false })
   void fullRunBoundsPagesAndCheckpointRanges(boolean sql) throws Exception
   {
      var keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      var config = new WormAuditQBitConfig().withCheckpointEveryLinks(RANGE)
         .withSigningKey(() -> new WormAuditQBitConfig.SigningKey("test", keys.getPrivate()))
         .withTrustedPublicKeys(Map.of("test", keys.getPublic()));
      var store = new InstrumentedStore(config, sql);
      var result = new WormAuditVerifier(config, PAGE).verify(store, null, NOW);
      assertThat(result.getBreaks()).isEmpty();
      assertThat(result.getLinksChecked()).isEqualTo(LINKS);
      assertThat(result.getFromLinkId()).isEqualTo(1);
      assertThat(result.getToLinkId()).isEqualTo(LINKS);
      assertThat(store.maxPage).isEqualTo(PAGE);
      assertThat(store.maxRange).isEqualTo(RANGE);
      assertThat(store.checkpointsRead).isEqualTo(26);
      assertThat(store.completenessVisited).isTrue();
      if(!sql)
      {
         store.links.get(0).withValue("detail_ids", "1,1,2");
         store.links.get(1).withValue("detail_ids", "2");
         store.links.get(2).withValue("detail_ids", "malformed");
         store.links.get(3).withValue("audit_id", 1L);
         store.audits.get(2).withValue("timestamp", null);
         store.audits.get(4).withValue("timestamp", NOW);
         store.details.addAll(List.of(new QRecord().withValue("id", 1L).withValue("auditId", 1L),
            new QRecord().withValue("id", 2L).withValue("auditId", 2L),
            new QRecord().withValue("id", 3L).withValue("auditId", 99999L),
            new QRecord().withValue("id", 4L).withValue("auditId", 3L)));
         var broken = new WormAuditVerifier(config, PAGE).verify(store, null, NOW);
         assertThat(broken.getBreaks()).extracting(finding -> finding.reason()).contains(
            "audit 1 is covered twice or more by the chain", "audit 4 is not covered by the chain",
            "audit 3 has no timestamp", "audit_detail 1 is covered twice or more by the chain",
            "audit_detail 2 is covered twice or more by the chain", "audit_detail 3 is not covered by the chain",
            "audit_detail 4 is not covered by the chain");
      }
      assertThatThrownBy(() -> new WormAuditVerifier(config, 0)).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> new WormAuditVerifier(config, 1001)).isInstanceOf(IllegalArgumentException.class);
   }


   /*******************************************************************************
    ** Fixture storage may retain its data; the verifier can only fetch bounded
    ** pages. Track the total hashes read between successive checkpoint requests.
    *******************************************************************************/
   private static class InstrumentedStore extends AuditStore
   {
      private final List<QRecord> audits = new ArrayList<>();
      private final List<QRecord> details = new ArrayList<>();
      private final List<QRecord> links = new ArrayList<>();
      private final List<QRecord> checkpoints = new ArrayList<>();
      private final boolean sql;
      private int maxPage;
      private int maxRange;
      private int rangeRead;
      private int checkpointsRead;
      private boolean inCheckpoints;
      private boolean completenessVisited;
      private boolean mainScanFinished;


      /*******************************************************************************
       ** Generate signed, valid content without involving the backend under test.
       *******************************************************************************/
      InstrumentedStore(WormAuditQBitConfig config, boolean sql) throws Exception
      {
         super(null);
         this.sql = sql;
         String previous = Hashes.GENESIS;
         for(long id = 1; id <= LINKS; id++)
         {
            QRecord audit = new QRecord().withValue("id", id).withValue("timestamp", NOW.minusSeconds(120))
               .withValue("auditTableId", 1).withValue("auditUserId", 1).withValue("recordId", id);
            audits.add(audit);
            String hash = Hashes.link(previous, AuditCanonical.bytes(audit, "fixture", "fixture", List.of()));
            links.add(new QRecord().withValue("id", id).withValue("audit_id", id).withValue("kind", "AUDIT")
               .withValue("detail_ids", "").withValue("prev_hash", previous).withValue("link_hash", hash).withValue("chained_at", NOW));
            previous = hash;
         }
         for(int start = 0; start < LINKS; start += RANGE)
         {
            checkpoints.add(Checkpoints.sign(links.subList(start, Math.min(start + RANGE, LINKS)), config, NOW)
               .withValue("id", (long) checkpoints.size() + 1));
         }
      }


      /*******************************************************************************
       ** No full-table read is ever permitted through this boundary.
       *******************************************************************************/
      @Override
      public List<QRecord> all(String table)
      {
         throw (new AssertionError("Unbounded verifier read: " + table));
      }


      /*******************************************************************************
       ** A fresh copied page prevents subList from retaining the fixture chain.
       *******************************************************************************/
      @Override
      public List<QRecord> page(String table, long after, int limit)
      {
         assertThat(limit).isBetween(1, PAGE);
         maxPage = Math.max(maxPage, limit);
         List<QRecord> source;
         if(table.equals(WormAuditTables.CHECKPOINT))
         {
            assertThat(mainScanFinished).isTrue();
            assertThat(limit).isEqualTo(1);
            maxRange = Math.max(maxRange, rangeRead);
            assertThat(rangeRead).isLessThanOrEqualTo(RANGE);
            rangeRead = 0;
            inCheckpoints = after < checkpoints.size();
            if(inCheckpoints)
            {
               checkpointsRead++;
            }
            source = checkpoints;
         }
         else if(table.equals(WormAuditTables.CHAIN))
         {
            source = links;
            if(after == LINKS && !inCheckpoints)
            {
               mainScanFinished = true;
            }
         }
         else
         {
            completenessVisited = true;
            source = table.equals("audit") ? audits : details;
         }
         int start = (int) Math.min(after, source.size());
         var page = new ArrayList<>(source.subList(start, Math.min(start + limit, source.size())));
         if(inCheckpoints && table.equals(WormAuditTables.CHAIN))
         {
            rangeRead += page.size();
         }
         return (page);
      }


      /*******************************************************************************
       ** Batch only the audit headers belonging to the current chain page.
       *******************************************************************************/
      @Override
      public List<QRecord> in(String table, String field, Collection<Long> ids)
      {
         assertThat(ids.size()).isLessThanOrEqualTo(PAGE);
         return (ids.stream().distinct().map(id -> (table.equals("audit") ? audits : details).get(id.intValue() - 1)).toList());
      }


      /*******************************************************************************
       ** Resolve detail parents without collecting audit history.
       *******************************************************************************/
      @Override
      public QRecord get(String table, long id)
      {
         return (id > audits.size() ? null : audits.get((int) id - 1));
      }


      /*******************************************************************************
       ** Stable lookup values match the fixture canonical documents.
       *******************************************************************************/
      @Override
      public String name(String table, Long id)
      {
         return ("fixture");
      }


      /*******************************************************************************
       ** Start at genesis.
       *******************************************************************************/
      @Override
      public QRecord anchor()
      {
         return (new QRecord().withValue("anchor_link_id", 0L).withValue("anchor_hash", Hashes.GENESIS));
      }


      /*******************************************************************************
       ** Exercise both SQL dispatch and portable non-memory completeness.
       *******************************************************************************/
      @Override
      public boolean isRdbms()
      {
         return (sql);
      }


      /*******************************************************************************
       ** Never permit the memory fallback in this test.
       *******************************************************************************/
      @Override
      public boolean isMemory()
      {
         return (false);
      }


      /*******************************************************************************
       ** SQL completeness has separate acceptance tests; verify dispatch here.
       *******************************************************************************/
      @Override
      public void completeness(Instant cutoff, VerificationResult result)
      {
         completenessVisited = true;
      }
   }
}
