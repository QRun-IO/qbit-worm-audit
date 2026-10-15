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

import java.sql.DriverManager;
import java.util.Map;
import java.util.UUID;
import com.kingsrook.qbits.wormaudit.chain.SweepFloors;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.core;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.lookups;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Tests and fixtures for rdbms chain test.
 *******************************************************************************/
class RdbmsChainTest
{
   /*******************************************************************************
    ** Verify real qqq rdbms actions anti join rollback and tamper.
    *******************************************************************************/
   @Test
   void realQqqRdbmsActionsAntiJoinRollbackAndTamper() throws Exception
   {
      String url =
            "jdbc:h2:mem:worm_"
                  + UUID.randomUUID()
                  + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var config = ChainVerificationTest.signed();
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""))
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         QContext.init(instance, new QSession());
         lookups();
         audit(1);
         detail(1, 1);
         var writer = new WormAuditChainer(config);
         assertThat(writer.chainOnce().links()).isEqualTo(1);
         assertThat(writer.chainOnce().links()).isZero();
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
         // Fail signing after append, verifying the real RDBMS transaction rolls back.
         var pins = config.getTrustedPublicKeys();
         config.withTrustedPublicKeys(Map.of());
         audit(2);
         assertThatThrownBy(writer::chainOnce)
               .hasMessageContaining("WORM audit operation failed");
         assertThat(STORE.all(WormAuditTables.CHAIN)).hasSize(1);
         config.withTrustedPublicKeys(pins);
         assertThat(writer.chainOnce().links()).isEqualTo(1);
         assertThat(STORE.all(WormAuditTables.CHAIN))
               .extracting(r -> r.getValueLong("id"))
               .containsExactly(1L, 2L);
         connection
               .createStatement()
               .execute("UPDATE audit_detail SET new_value='changed' WHERE id=1");
         assertThat(new WormAuditVerifier(config).verify().getBreaks())
               .anyMatch(b -> b.reason().contains("audit_detail 1"));
      }
   }

   /*******************************************************************************
    ** Exercise multiple keyset pages, capped checkpoints and bounded SQL query counts.
    *******************************************************************************/
   @Test
   void batchesPagesAndCheckpointRanges() throws Exception
   {
      String url = "jdbc:h2:mem:pages_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var config = ChainVerificationTest.signed().withBatchSize(1500).withCheckpointEveryLinks(400).withCheckpointEveryMinutes(1);
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""); var statement = connection.createStatement())
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         QContext.init(instance, new QSession());
         lookups();
         statement.execute("INSERT INTO audit(id,audit_table_id,audit_user_id,record_id,timestamp) SELECT x,1,1,17,CURRENT_TIMESTAMP - INTERVAL '2' MINUTE FROM SYSTEM_RANGE(1,1005) series(x)");
         statement.execute("INSERT INTO audit_detail(id,audit_id,field_name,new_value) SELECT x,x,'title','new' FROM SYSTEM_RANGE(1,1005) series(x)");
         statement.execute("SET QUERY_STATISTICS TRUE");
         var writer = new WormAuditChainer(config);
         var now = java.time.Instant.now();
         var counts = writer.chainOnce(now);
         assertThat(counts.links()).isEqualTo(1005);
         assertThat(counts.checkpoints()).isEqualTo(2);
         assertSelectCount(connection, 100);
         assertThat(STORE.last(WormAuditTables.CHECKPOINT).getValueInstant("created_at")).isCloseTo(now, org.assertj.core.api.Assertions.within(1, java.time.temporal.ChronoUnit.SECONDS));
         statement.execute("SET QUERY_STATISTICS FALSE");
         statement.execute("SET QUERY_STATISTICS TRUE");
         assertThat(writer.chainOnce(now.plusSeconds(61)).checkpoints()).isEqualTo(1);
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
         assertSelectCount(connection, 100);
         assertThat(STORE.all(WormAuditTables.CHECKPOINT)).extracting(r -> r.getValueLong("link_count")).containsExactly(400L, 400L, 205L);
         statement.execute("UPDATE audit_detail SET new_value='changed' WHERE id=1001");
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("audit_detail 1,001"));
         statement.execute("DELETE FROM worm_audit_chain WHERE id=1000");
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("gap"));
      }
   }


   /*******************************************************************************
    ** Assert actual query executions stay proportional to batches, not row count.
    *******************************************************************************/
   private void assertSelectCount(java.sql.Connection connection, int limit) throws Exception
   {
      try(var statement = connection.createStatement(); var rows = statement.executeQuery(
         "SELECT COALESCE(SUM(EXECUTION_COUNT),0) FROM INFORMATION_SCHEMA.QUERY_STATISTICS WHERE UPPER(SQL_STATEMENT) LIKE 'SELECT%'"))
      {
         rows.next();
         assertThat(rows.getLong(1)).isLessThan(limit);
      }
   }


   /*******************************************************************************
    ** Poll only the lookback window and report older omissions with exact bounded ids.
    *******************************************************************************/
   @Test
   void lateWindowAndCompletenessOffenderLimit() throws Exception
   {
      String url = "jdbc:h2:mem:window_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var config = new WormAuditQBitConfig().withBatchSize(500);
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""); var statement = connection.createStatement())
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         QContext.init(instance, new QSession());
         lookups();
         audit(1);
         statement.execute("INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES(2,1,1,CURRENT_TIMESTAMP - INTERVAL '2' MINUTE)");
         var writer = new WormAuditChainer(config);
         writer.chainOnce();
         detail(1, 1);
         detail(2, 2);
         assertThat(writer.chainOnce().lateDetails()).isEqualTo(1);
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("audit_detail 1 is not covered"));
         statement.execute("INSERT INTO worm_audit_chain SELECT 99,kind,audit_id,detail_ids,prev_hash,link_hash,chained_at FROM worm_audit_chain WHERE id=3");
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("audit_detail 2 is covered twice"));
         statement.execute("DELETE FROM worm_audit_chain WHERE id=99");
         statement.execute("INSERT INTO audit_detail(id,audit_id) SELECT x,1 FROM SYSTEM_RANGE(3,107) series(x)");
         var result = new WormAuditVerifier(config).verify();
         assertThat(result.getBreakCount()).isEqualTo(106);
         assertThat(result.getBreaks()).hasSize(100);
         assertThat(result.getBreaks().getFirst().reason()).contains("audit_detail 1 is not covered");
         assertThat(result.getBreaks().getLast().reason()).contains("audit_detail 101 is not covered");
         assertThat(result.getWarnings()).anyMatch(w -> w.contains("106 coverage offenders"));
         statement.execute("INSERT INTO audit(id,timestamp) SELECT x,CURRENT_TIMESTAMP - INTERVAL '2' MINUTE FROM SYSTEM_RANGE(2000,2104) series(x)");
         result = new WormAuditVerifier(config).verify();
         assertThat(result.getBreakCount()).isEqualTo(211);
         assertThat(result.getBreaks()).hasSize(200);
         assertThat(result.getBreaks().getFirst().reason()).contains("audit 2,000 is not covered");
         assertThat(result.getBreaks().get(99).reason()).contains("audit 2,099 is not covered");
      }
   }


   /*******************************************************************************
    ** Cutoffs are UTC local values for timestamp columns, independent of JVM zone.
    *******************************************************************************/
   @Test
   void withoutTimezoneCutoffInChicago() throws Exception
   {
      var original = java.util.TimeZone.getDefault();
      String url = "jdbc:h2:mem:timezone_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var config = new WormAuditQBitConfig();
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""); var statement = connection.createStatement())
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         statement.execute("ALTER TABLE audit ALTER COLUMN timestamp timestamp without time zone");
         QContext.init(instance, new QSession());
         lookups();
         statement.execute("INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES(1,1,1,TIMESTAMP '2026-10-13 12:00:00'),(2,1,1,TIMESTAMP '2026-10-13 12:01:30')");
         java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("America/Chicago"));
         assertThat(new WormAuditChainer(config).chainOnce(java.time.Instant.parse("2026-10-13T12:02:00Z")).audits()).isEqualTo(1);
         assertThat(STORE.all(WormAuditTables.CHAIN)).extracting(r -> r.getValueLong("audit_id")).containsExactly(1L);
         java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("UTC"));
         assertThat(new WormAuditVerifier(config).verify(java.util.Set.of(1L)).getBreaks()).isEmpty();
      }
      finally
      {
         java.util.TimeZone.setDefault(original);
      }
   }


   /*******************************************************************************
    ** Without a coverage trigger the writer records coverage itself, and the
    ** sweep floors advance only past settled ids: a later header and a late
    ** detail for an old, already chained header are both still chained.
    *******************************************************************************/
   @Test
   void coverageRowsAndSweepFloors() throws Exception
   {
      String url = "jdbc:h2:mem:floors_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE";
      var config = new WormAuditQBitConfig().withBatchSize(500);
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""); var statement = connection.createStatement())
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         QContext.init(instance, new QSession());
         lookups();
         statement.execute("INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES(1,1,1,CURRENT_TIMESTAMP - INTERVAL '2' MINUTE)");
         detail(10, 1);
         detail(20, 1);
         var writer = new WormAuditChainer(config);
         var floors = SweepFloors.of(config);
         var now = java.time.Instant.now();
         assertThat(writer.chainOnce(now).audits()).isEqualTo(1);
         assertThat(STORE.query(WormAuditTables.CHAIN_DETAIL, new com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter())).extracting(r -> r.getValueLong("detail_id") + "@" + r.getValueLong("chain_id"))
            .containsExactlyInAnyOrder("10@1", "20@1");
         assertThat(floors.audit()).isZero();
         assertThat(writer.chainOnce(now.plusSeconds(600)).links()).isZero();
         assertThat(floors.audit()).isEqualTo(1);
         assertThat(floors.detail()).isEqualTo(20);
         detail(30, 1);
         statement.execute("INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES(2,1,1,CURRENT_TIMESTAMP - INTERVAL '2' MINUTE)");
         detail(40, 2);
         var counts = writer.chainOnce(now.plusSeconds(1200));
         assertThat(counts.audits()).isEqualTo(1);
         assertThat(counts.lateDetails()).isEqualTo(1);
         assertThat(STORE.query(WormAuditTables.CHAIN_DETAIL, new com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter())).hasSize(4);
         assertThat(writer.chainOnce(now.plusSeconds(1800)).links()).isZero();
         assertThat(floors.audit()).isEqualTo(2);
         assertThat(floors.detail()).isEqualTo(40);
         // A detail whose id sits below the floor (its transaction committed very late)
         // is skipped by floored ticks and chained by the next hourly full sweep.
         statement.execute("INSERT INTO audit_detail(id,audit_id,field_name,new_value) VALUES(5,2,'title','late')");
         assertThat(writer.chainOnce(now.plusSeconds(2400)).lateDetails()).isZero();
         assertThat(writer.chainOnce(now.plus(SweepFloors.FULL_SWEEP_EVERY)).lateDetails()).isEqualTo(1);
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
         statement.execute("DELETE FROM worm_audit_chain_detail WHERE detail_id=30");
         statement.execute("INSERT INTO worm_audit_chain_detail(detail_id,chain_id) VALUES(30,1)");
         assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("audit_detail 30 has a detail coverage row that disagrees"));
      }
   }
}
