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

import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.OLD;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.core;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.remove;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.tamper;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Tests and fixtures for chain verification test.
 *******************************************************************************/
class ChainVerificationTest
{
   /*******************************************************************************
    ** Verify signed.
    *******************************************************************************/
   static WormAuditQBitConfig signed() throws Exception
   {
      var pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      return (new WormAuditQBitConfig()
            .withCheckpointEveryLinks(1)
            .withSigningKey(() -> new WormAuditQBitConfig.SigningKey("test", pair.getPrivate()))
            .withTrustedPublicKeys(Map.of("test", pair.getPublic())));
   }

   /*******************************************************************************
    ** Verify late headers details and chunk boundaries.
    *******************************************************************************/
   @Test
   void lateHeadersDetailsAndChunkBoundaries() throws Exception
   {
      var config = signed().withBatchSize(1);
      init(config);
      audit(20);
      detail(1, 20);
      var writer = new WormAuditChainer(config);
      assertThat(writer.chainOnce().audits()).isEqualTo(1);
      audit(1);
      detail(2, 1);
      detail(3, 20);
      assertThat(writer.chainOnce().lateDetails()).isEqualTo(1);
      for(long i = 4; i <= 260; i++)
      {
         detail(i, 1);
      }
      assertThat(writer.chainOnce().lateDetails()).isEqualTo(257);
      var links = STORE.all(WormAuditTables.CHAIN);
      assertThat(links).extracting(r -> r.getValueLong("id")).containsExactly(1L, 2L, 3L, 4L, 5L);
      assertThat(links).allMatch(r -> AuditStore.detailIds(r).size() <= 250);
      var result = new WormAuditVerifier(config).verify();
      assertThat(result.getBreaks()).isEmpty();
      assertThat(result.getLinksChecked()).isEqualTo(5);
      assertThat(result.getFromLinkId()).isEqualTo(1);
      assertThat(result.getToLinkId()).isEqualTo(5);
      assertThat(writer.chainOnce().links()).isZero();
   }

   /*******************************************************************************
    ** Verify overflow at initial chain and settling and elapsed checkpoint.
    *******************************************************************************/
   @Test
   void overflowAtInitialChainAndSettlingAndElapsedCheckpoint() throws Exception
   {
      var config = signed().withCheckpointEveryLinks(10000).withCheckpointEveryMinutes(1);
      init(config);
      audit(1);
      for(long i = 1; i <= 251; i++)
      {
         detail(i, 1);
      }
      var writer = new WormAuditChainer(config);
      assertThat(writer.chainOnce(OLD.plusSeconds(30)).links()).isZero();
      Instant now = Instant.now();
      assertThat(writer.chainOnce(now).links()).isEqualTo(2);
      assertThat(STORE.all(WormAuditTables.CHECKPOINT)).isEmpty();
      assertThat(writer.chainOnce(now.plusSeconds(61)).checkpoints()).isEqualTo(1);
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
      config.withSigningKey(null);
      assertThat(new WormAuditVerifier(config).verify().getWarnings())
            .contains("no signing key configured");
   }

   /*******************************************************************************
    ** Verify detects breaks.
    *******************************************************************************/
   @ParameterizedTest
   @ValueSource(
         strings =
         {
            "content",
            "headerDeleted",
            "detailDeleted",
            "inserted",
            "detailInserted",
            "gap",
            "previous",
            "reorder",
            "forged",
            "untrusted",
            "merkle",
            "head",
            "duplicate",
            "kind",
            "lookup",
            "range",
            "nullCheckpoint",
            "nullPrevious",
            "nullTimestamp"
         })
   void detectsBreaks(String scenario) throws Exception
   {
      var config = signed();
      init(config);
      audit(1);
      detail(1, 1);
      audit(2);
      detail(2, 2);
      new WormAuditChainer(config).chainOnce();
      String expected;
      switch(scenario)
      {
         case "content" ->
         {
            tamper("auditDetail", 1, "newValue", "tampered");
            expected =
                  "Break at link 1 (audit 1, table cms_page, record 17): content differs from"
                     + " the chained hash (audit_detail 1)";
         }
         case "headerDeleted" ->
         {
            remove("audit", 1);
            expected = "audit header is missing";
         }
         case "detailDeleted" ->
         {
            remove("auditDetail", 1);
            expected = "audit_detail 1 is missing";
         }
         case "inserted" ->
         {
            audit(3);
            expected = "audit 3 is not covered";
         }
         case "detailInserted" ->
         {
            detail(3, 1);
            expected = "audit_detail 3 is not covered";
         }
         case "gap" ->
         {
            remove(WormAuditTables.CHAIN, 1);
            expected = "gap";
         }
         case "previous" ->
         {
            tamper(WormAuditTables.CHAIN, 2, "prev_hash", Hashes.GENESIS);
            expected = "prev-hash discontinuity";
         }
         case "reorder" ->
         {
            tamper(WormAuditTables.CHAIN, 1, "audit_id", 2L);
            expected = "another audit";
         }
         case "forged" ->
         {
            tamper(WormAuditTables.CHECKPOINT, 1, "signature", "AA==");
            expected = "checkpoint 1: signature does not verify";
         }
         case "untrusted" ->
         {
            config.withTrustedPublicKeys(Map.of());
            expected = "untrusted key";
         }
         case "merkle" ->
         {
            tamper(WormAuditTables.CHECKPOINT, 1, "merkle_root", Hashes.GENESIS);
            expected = "merkle mismatch";
         }
         case "head" ->
         {
            tamper(WormAuditTables.CHECKPOINT, 1, "head_hash", Hashes.GENESIS);
            expected = "head mismatch";
         }
         case "duplicate" ->
         {
            tamper(WormAuditTables.CHAIN, 1, "detail_ids", "1,1");
            expected = "audit_detail 1 is covered twice";
         }
         case "kind" ->
         {
            tamper(WormAuditTables.CHAIN, 1, "kind", "INVALID");
            expected = "invalid kind";
         }
         case "lookup" ->
         {
            tamper("auditTable", 1, "name", "renamed");
            expected = "content differs";
         }
         case "nullCheckpoint" ->
         {
            tamper(WormAuditTables.CHECKPOINT, 1, "signature", null);
            expected = "malformed checkpoint";
         }
         case "nullPrevious" ->
         {
            tamper(WormAuditTables.CHAIN, 1, "prev_hash", null);
            expected = "malformed link";
         }
         case "nullTimestamp" ->
         {
            tamper("audit", 1, "timestamp", null);
            expected = "missing audit timestamp";
         }
         default ->
         {
            tamper(WormAuditTables.CHECKPOINT, 1, "link_count", 22L);
            expected = "invalid link range";
         }
      }
      var result = new WormAuditVerifier(config).verify();
      assertThat(result.passed()).isFalse();
      assertThat(result.getBreaks()).anyMatch(b -> b.reason().contains(expected));
   }

   /*******************************************************************************
    ** Verify selection does not run completeness and checks boundary.
    *******************************************************************************/
   @Test
   void selectionDoesNotRunCompletenessAndChecksBoundary() throws Exception
   {
      var config = signed();
      init(config);
      audit(1);
      audit(2);
      new WormAuditChainer(config).chainOnce();
      audit(3);
      assertThat(new WormAuditVerifier(config).verify(Set.of(2L)).passed()).isTrue();
      assertThat(new WormAuditVerifier(config).verify(Set.of()).getLinksChecked()).isZero();
      assertThat(new WormAuditVerifier(config).verify(Set.of(99L)).getBreaks())
            .anyMatch(b -> b.reason().contains("Missing selected link 99"));
      tamper(WormAuditTables.CHAIN, 2, "prev_hash", Hashes.GENESIS);
      assertThat(new WormAuditVerifier(config).verify(Set.of(2L)).getBreaks())
            .anyMatch(b -> b.reason().contains("prev-hash"));
   }

   /*******************************************************************************
    ** Verify continues after purge anchor including empty live chain.
    *******************************************************************************/
   @Test
   void continuesAfterPurgeAnchorIncludingEmptyLiveChain() throws Exception
   {
      var config = signed();
      init(config);
      audit(1);
      detail(1, 1);
      audit(2);
      new WormAuditChainer(config).chainOnce();
      var first = STORE.get(WormAuditTables.CHAIN, 1);
      STORE.insert(
            WormAuditTables.PURGE,
            List.of(
                  new com.kingsrook.qqq.backend.core.model.data.QRecord()
                        .withValue("outcome", "PURGED")
                        .withValue("anchor_link_id", 1L)
                        .withValue("anchor_hash", first.getValueString("link_hash"))));
      remove("auditDetail", 1);
      remove("audit", 1);
      remove(WormAuditTables.CHAIN, 1);
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
      var last = STORE.get(WormAuditTables.CHAIN, 2);
      STORE.insert(
            WormAuditTables.PURGE,
            List.of(
                  new com.kingsrook.qqq.backend.core.model.data.QRecord()
                        .withValue("outcome", "PURGED")
                        .withValue("anchor_link_id", 2L)
                        .withValue("anchor_hash", last.getValueString("link_hash"))));
      remove("audit", 2);
      remove(WormAuditTables.CHAIN, 2);
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
      audit(3);
      new WormAuditChainer(config).chainOnce();
      assertThat(STORE.all(WormAuditTables.CHAIN))
            .extracting(r -> r.getValueLong("id"))
            .containsExactly(3L);
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
   }

   /*******************************************************************************
    ** Findings retain bounded diagnostics while recording the complete failure count.
    *******************************************************************************/
   @Test
   void boundedDiagnosticsPreserveTotalCount() throws Exception
   {
      init(new WormAuditQBitConfig());
      var result = new com.kingsrook.qbits.wormaudit.verify.VerificationResult();
      for(long id = 1; id <= 1200; id++)
      {
         result.add(id, id, "gap");
         result.warn("warning " + id);
      }
      result.omitted(20);
      assertThat(result.getBreaks()).hasSize(1000);
      assertThat(result.getWarnings()).hasSize(100);
      assertThat(result.getBreakCount()).isEqualTo(1220);
      assertThat(result.passed()).isFalse();
      assertThat(com.kingsrook.qbits.wormaudit.processes.VerificationRuns.save(result, "USER").getValueLong("break_count")).isEqualTo(1220);
   }

}
