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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.core;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.lookups;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Tests and fixtures for postgres acceptance test.
 *******************************************************************************/
@ExtendWith(RequiresDockerCondition.class)
@Testcontainers
class PostgresAcceptanceTest
{
   @Container
   static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

   WormAuditQBitConfig config;
   QInstance instance;

   /*******************************************************************************
    ** Verify owner.
    *******************************************************************************/
   Connection owner() throws SQLException
   {
      return (DriverManager.getConnection(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
   }

   /*******************************************************************************
    ** Verify app.
    *******************************************************************************/
   Connection app() throws SQLException
   {
      return (DriverManager.getConnection(POSTGRES.getJdbcUrl(), "app", "fixture"));
   }

   /*******************************************************************************
    ** Verify sql.
    *******************************************************************************/
   void sql(Connection c, String sql) throws SQLException
   {
      try(var s = c.createStatement())
      {
         s.execute(sql);
      }
   }

   /*******************************************************************************
    ** Verify count.
    *******************************************************************************/
   long count(Connection c, String sql) throws SQLException
   {
      try(var s = c.createStatement();
            var r = s.executeQuery(sql))
      {
         r.next();
         return (r.getLong(1));
      }
   }

   /*******************************************************************************
    ** Verify database.
    *******************************************************************************/
   @BeforeEach
   void database() throws Exception
   {
      config = ChainVerificationTest.signed().withSettleHorizonSeconds(0);
      try(var c = owner())
      {
         sql(
               c,
               "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT USAGE ON SCHEMA public"
                  + " TO PUBLIC");
         sql(
               c,
               "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='app') THEN"
                  + " CREATE ROLE app LOGIN PASSWORD 'fixture'; END IF; END $$");
         instance = RdbmsTestSupport.instance(POSTGRES.getJdbcUrl(), "app", "fixture", config, true);
         RdbmsTestSupport.createTables(c, instance, true);
         String ddl = WormAuditDdl.postgres(config);
         sql(c, ddl);
         sql(c, ddl);
      }
      QContext.init(instance, new QSession());
      lookups();
   }

   /*******************************************************************************
    ** Home setup probes see dropped/disabled guards, missing purge and runtime ownership.
    ** This test uses the same Docker condition as the existing PostgreSQL suite.
    *******************************************************************************/
   @Test
   void homeSetupWarnings() throws Exception
   {
      var storage = new com.kingsrook.qbits.wormaudit.demo.MemorySealedStore();
      var clean = com.kingsrook.qbits.wormaudit.app.WormAuditHomeData.load(config, storage, java.time.Instant.now());
      assertThat(clean.warnings()).contains("Daily verification has never run").noneMatch(w -> w.contains("guard") && w.contains("settings"));
      try(var connection = owner())
      {
         sql(connection, "UPDATE worm_audit_settings SET audit_retention_years=7 WHERE id=1");
         config.invalidateSettings();
         assertThat(com.kingsrook.qbits.wormaudit.app.WormAuditHomeData.load(config, storage, java.time.Instant.now()).warnings())
            .anyMatch(w -> w.contains("purge function's compiled interval (6 years)"));
         sql(connection, WormAuditDdl.postgres(config));
         assertThat(count(connection, "SELECT audit_retention_years FROM worm_audit_settings WHERE id=1")).isEqualTo(7);
         sql(connection, "UPDATE worm_audit_settings SET audit_retention_years=6 WHERE id=1");
         config.invalidateSettings();
         sql(connection, "DROP TRIGGER worm_audit_row_guard ON audit_detail");
         sql(connection, "ALTER TABLE worm_audit_chain DISABLE TRIGGER worm_audit_truncate_guard");
         sql(connection, "DROP FUNCTION public.worm_audit_purge(timestamptz)");
      }
      var missing = com.kingsrook.qbits.wormaudit.app.WormAuditHomeData.load(config, storage, java.time.Instant.now());
      assertThat(missing.warnings()).contains("Missing or disabled worm_audit_row_guard on audit_detail",
         "Missing or disabled worm_audit_truncate_guard on worm_audit_chain", "Retention purge function is missing");
      instance = RdbmsTestSupport.instance(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword(), config, true);
      QContext.init(instance, new QSession());
      assertThat(com.kingsrook.qbits.wormaudit.app.WormAuditHomeData.load(config, storage, java.time.Instant.now()).warnings())
         .contains("Runtime role owns audit table audit", "Runtime role owns audit table worm_audit_purge");
   }

   /*******************************************************************************
    ** Verify grants triggers lookup rules and spoofed flag.
    *******************************************************************************/
   @Test
   void grantsTriggersLookupRulesAndSpoofedFlag() throws Exception
   {
      audit(1);
      detail(1, 1);
      new WormAuditChainer(config).chainOnce();
      try(var c = owner();
            var runtime = app())
      {
         assertThatThrownBy(() -> sql(runtime,
            "INSERT INTO worm_audit_chain(id,kind,audit_id,detail_ids,prev_hash,link_hash,chained_at) "
               + "SELECT 99,'LATE_DETAIL',audit_id,detail_ids,prev_hash,link_hash,chained_at FROM worm_audit_chain WHERE id=1"))
            .isInstanceOf(SQLException.class).satisfies(e -> assertThat(((SQLException) e).getSQLState()).isEqualTo("23505"));

         for(String table :
               List.of("worm_audit_export", "worm_audit_verification", "worm_audit_purge"))
         {
            sql(c, "INSERT INTO " + table + " DEFAULT VALUES");
         }
         List<String> tables =
               List.of(
                     "audit",
                     "audit_detail",
                     "worm_audit_chain",
                     "worm_audit_checkpoint",
                     "worm_audit_export",
                     "worm_audit_verification",
                     "worm_audit_purge");
         for(String table : tables)
         {
            assertThat(
                        count(
                              c,
                              "SELECT has_table_privilege('app','"
                                    + table
                                    + "','UPDATE')::int"))
                  .isZero();
            assertThat(
                        count(
                              c,
                              "SELECT has_table_privilege('app','"
                                    + table
                                    + "','DELETE')::int"))
                  .isZero();
            assertThat(
                        count(
                              c,
                              "SELECT has_table_privilege('app','"
                                    + table
                                    + "','TRUNCATE')::int"))
                  .isZero();
            // PostgreSQL checks grants before firing triggers: an unprivileged app
            // receives 42501. Temporarily grant DML to prove the trigger defense too.
            assertThatThrownBy(() -> sql(runtime, "UPDATE " + table + " SET id=id"))
                  .isInstanceOf(SQLException.class)
                  .satisfies(
                        e ->
                              assertThat(((SQLException) e).getSQLState())
                                    .isEqualTo("42501"));
            sql(c, "GRANT UPDATE, DELETE, TRUNCATE ON " + table + " TO app");
            // A table a foreign key references (audit, checkpoint, export) refuses TRUNCATE before
            // its guard runs; TRUNCATE ... CASCADE (owner) reaches the guards, which refuse it.
            if(count(c, "SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='" + table + "'::regclass") > 0)
            {
               assertThatThrownBy(() -> sql(runtime, "TRUNCATE " + table))
                  .isInstanceOf(SQLException.class)
                  .hasMessageContaining("referenced in a foreign key constraint");
               assertThatThrownBy(() -> sql(c, "TRUNCATE " + table + " CASCADE"))
                  .isInstanceOf(SQLException.class)
                  .hasMessageContaining("worm_audit:");
            }
            boolean referenced = count(c, "SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='" + table + "'::regclass") > 0;
            for(String operation : referenced
               ? List.of("UPDATE " + table + " SET id=id", "DELETE FROM " + table)
               : List.of("UPDATE " + table + " SET id=id", "DELETE FROM " + table, "TRUNCATE " + table))
            {
               assertThatThrownBy(() -> sql(runtime, operation))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("worm_audit:")
                        .satisfies(
                              e ->
                                    assertThat(((SQLException) e).getSQLState())
                                          .isEqualTo("P0001"));
            }
         }
         sql(runtime, "SELECT set_config('worm_audit.purging','on',false)");
         assertThatThrownBy(() -> sql(runtime, "DELETE FROM audit"))
               .hasMessageContaining("worm_audit:");
         sql(runtime, "UPDATE audit_table SET label='Allowed label'");
         sql(runtime, "UPDATE audit_user SET modify_date=now()");
         for(String table : List.of("audit_table", "audit_user"))
         {
            sql(c, "GRANT UPDATE, DELETE ON " + table + " TO app");
            assertThatThrownBy(() -> sql(runtime, "UPDATE " + table + " SET name='renamed'"))
                  .hasMessageContaining("worm_audit:");
            assertThatThrownBy(() -> sql(runtime, "UPDATE " + table + " SET id=id+1"))
                  .hasMessageContaining("worm_audit:");
            assertThatThrownBy(() -> sql(runtime, "DELETE FROM " + table))
                  .hasMessageContaining("worm_audit:");
            assertThatThrownBy(() -> sql(c, "TRUNCATE " + table))
                  .hasMessageContaining("worm_audit:");
            sql(runtime, "UPDATE " + table + " SET modify_date=now()");
         }
         sql(runtime, "UPDATE audit_table SET label='New label'");
         sql(c, WormAuditDdl.postgres(config));
         assertThat(
                     count(
                           c,
                           "SELECT"
                              + " has_function_privilege('app','worm_audit_purge(timestamptz)','EXECUTE')::int"))
               .isZero();
      }
   }

   /*******************************************************************************
    ** Verify retention refusal purge anchor and real backend tamper.
    *******************************************************************************/
   @Test
   void retentionRefusalPurgeAnchorAndRealBackendTamper() throws Exception
   {
      audit(1);
      detail(1, 1);
      audit(2);
      detail(2, 2);
      // A live suffix remains after the expired prefix is removed.
      try(var c = owner())
      {
         sql(
               c,
               "INSERT INTO audit(id,audit_table_id,audit_user_id,record_id,message,timestamp)"
                  + " VALUES(3,1,1,17,'Record was Edited',now()-interval '2 minutes')");
      }
      new WormAuditChainer(config).chainOnce();
      assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
      String anchor = STORE.get(WormAuditTables.CHAIN, 2).getValueString("link_hash");
      try(var c = owner())
      {
         sql(
               c,
               "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='purge_login')"
                  + " THEN CREATE ROLE purge_login LOGIN PASSWORD 'purger-fixture'; END IF;"
                  + " END $$; GRANT worm_audit_purger TO purge_login");
      }
      try(var purger =
            DriverManager.getConnection(
                  POSTGRES.getJdbcUrl(), "purge_login", "purger-fixture"))
      {
         sql(purger, "SELECT worm_audit_purge(now())");
         assertThat(STORE.all(WormAuditTables.PURGE).getFirst().getValueString("outcome"))
               .isEqualTo("REFUSED");
         sql(purger, "SELECT worm_audit_purge(now()-interval '6 years')");
      }
      var purge = STORE.all(WormAuditTables.PURGE).getLast();
      assertThat(purge.getValueString("outcome")).isEqualTo("PURGED");
      assertThat(purge.getValueString("requested_by")).isEqualTo("purge_login");
      assertThat(purge.getValueLong("audits_deleted")).isEqualTo(2);
      assertThat(purge.getValueLong("details_deleted")).isEqualTo(2);
      assertThat(purge.getValueLong("links_deleted")).isEqualTo(2);
      assertThat(purge.getValueString("anchor_hash")).isEqualTo(anchor);
      assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
      detail(3, 3);
      new WormAuditChainer(config).chainOnce();
      try(var c = owner())
      {
         sql(
               c,
               "ALTER TABLE audit_detail DISABLE TRIGGER ALL; UPDATE audit_detail SET"
                  + " new_value='tampered' WHERE id=3; ALTER TABLE audit_detail ENABLE"
                  + " TRIGGER ALL");
      }
      assertThat(new WormAuditVerifier(config).verify().getBreaks())
            .anyMatch(
                  b ->
                        b.reason()
                                    .contains(
                                          "Break at link 4 (audit 3, table cms_page,"
                                             + " record 17)")
                              && b.reason().contains("audit_detail 3"));
   }

   /*******************************************************************************
    ** Verify prefix cannot split an audit and advisory lock skips tick.
    *******************************************************************************/
   @Test
   void prefixCannotSplitAnAuditAndAdvisoryLockSkipsTick() throws Exception
   {
      // This retention fixture deliberately polls a detail for a six-year-old header.
      setting("late_detail_lookback_hours", 24 * 365 * 10);
      audit(1);
      new WormAuditChainer(config).chainOnce();
      try(var c = owner())
      {
         sql(
               c,
               "INSERT INTO audit(id,audit_table_id,audit_user_id,record_id,message,timestamp)"
                  + " VALUES(2,1,1,17,'Record was Edited',now()-interval '2 minutes')");
      }
      new WormAuditChainer(config).chainOnce();
      detail(1, 1);
      new WormAuditChainer(config).chainOnce();
      try(var c = owner())
      {
         sql(c, "SELECT worm_audit_purge(now()-interval '6 years')");
         assertThat(STORE.all(WormAuditTables.PURGE).getLast().getValueString("outcome"))
               .isEqualTo("REFUSED");
         assertThat(STORE.all(WormAuditTables.CHAIN)).hasSize(3);
         c.setAutoCommit(false);
         sql(c, "SELECT pg_advisory_xact_lock(" + WormAuditChainer.ADVISORY_LOCK + ")");
         assertThat(new WormAuditChainer(config).chainOnce().skipped()).isTrue();
         c.rollback();
      }
   }

   /*******************************************************************************
    ** Verify eight writers and three chainers with late commits.
    *******************************************************************************/
   @Test
   void eightWritersAndThreeChainersWithLateCommits() throws Exception
   {
      var done = new AtomicBoolean(false);
      var executor = Executors.newFixedThreadPool(11);
      List<Future<?>> writers = new ArrayList<>();
      List<Future<?>> chainers = new ArrayList<>();
      try
      {
         for(int thread = 0; thread < 8; thread++)
         {
            final int writer = thread;
            writers.add(
                  executor.submit(
                        () ->
                        {
                           try(var c = app())
                           {
                              for(int i = 0; i < 8; i++)
                              {
                                 long id = 1000L + writer * 100 + i;
                                 c.setAutoCommit(false);
                                 sql(
                                       c,
                                       "INSERT INTO"
                                          + " audit(id,audit_table_id,audit_user_id,record_id,message,timestamp)"
                                          + " VALUES("
                                             + id
                                             + ",1,1,17,'Record was"
                                             + " Edited',now()-interval '2"
                                             + " minutes')");
                                 if(i % 2 == 0)
                                 {
                                    c.commit();
                                 }
                                 Thread.sleep(5L * (writer + 1));
                                 sql(
                                       c,
                                       "INSERT INTO"
                                          + " audit_detail(id,audit_id,field_name,message,old_value,new_value)"
                                          + " VALUES("
                                             + id
                                             + ","
                                             + id
                                             + ",'title','Changed"
                                             + " Title','old','new')");
                                 c.commit();
                              }
                           }
                           catch(Exception e)
                           {
                              throw new RuntimeException(e);
                           }
                        }));
         }
         for(int i = 0; i < 3; i++)
         {
            chainers.add(
                     executor.submit(
                           () ->
                           {
                              QContext.init(instance, new QSession());
                              try
                              {
                                 do
                                 {
                                    new WormAuditChainer(config).chainOnce();
                                    Thread.sleep(10);
                                 } while(!done.get());
                              }
                              catch(Exception e)
                              {
                                 throw new RuntimeException(e);
                              }
                           }));
         }
         for(var writer : writers)
         {
            writer.get(90, TimeUnit.SECONDS);
         }
         done.set(true);
         for(var chainer : chainers)
         {
            chainer.get(90, TimeUnit.SECONDS);
         }
      }
      finally
      {
         done.set(true);
         executor.shutdownNow();
      }
      new WormAuditChainer(config).chainOnce();
      var links = STORE.all(WormAuditTables.CHAIN);
      for(int i = 0; i < links.size(); i++)
      {
         assertThat(links.get(i).getValueLong("id")).isEqualTo(i + 1L);
      }
      assertThat(links.stream().filter(r -> "AUDIT".equals(r.getValueString("kind"))).count())
            .isEqualTo(64);
      assertThat(links.stream().flatMap(r -> AuditStore.detailIds(r).stream()).toList())
            .hasSize(64)
            .doesNotHaveDuplicates();
      assertThat(new WormAuditVerifier(config).verify().getBreaks()).isEmpty();
   }

   /*******************************************************************************
    ** Even the function owner cannot authorize direct deletes by setting a GUC.
    *******************************************************************************/
   @Test
   void ownerCannotSpoofPurgeStack() throws Exception
   {
      audit(1);
      detail(1, 1);
      try(var connection = owner())
      {
         sql(connection, "ALTER TABLE audit ALTER COLUMN timestamp TYPE timestamp without time zone USING timestamp AT TIME ZONE 'UTC'");
         sql(connection, "INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES"
            + "(2,1,1,(now() AT TIME ZONE 'UTC')-interval '6 years'-interval '1 hour')");
      }
      new WormAuditChainer(config).chainOnce();
      try(var connection = owner())
      {
         sql(connection, "SELECT set_config('worm_audit.purging','on',false)");
         for(String table : List.of("audit", "audit_detail", "worm_audit_chain"))
         {
            assertThatThrownBy(() -> sql(connection, "DELETE FROM " + table + " WHERE id=1"))
               .isInstanceOf(SQLException.class).hasMessageContaining("worm_audit:");
         }
         assertThat(count(connection, "SELECT count(*) FROM worm_audit_purge")).isZero();
         // This succeeds only if the PG16 context text matches the stack guard.
         sql(connection, "SET timezone='America/Chicago'");
         sql(connection, "SELECT worm_audit_purge(now()-interval '6 years')");
         assertThat(count(connection, "SELECT count(*) FROM audit")).isZero();
         assertThat(count(connection, "SELECT count(*) FROM worm_audit_purge WHERE outcome='PURGED'")).isEqualTo(1);
      }
   }


   /*******************************************************************************
    ** A UTC without-tz audit column settles identically in a Chicago JVM/session.
    *******************************************************************************/
   @Test
   void chainerUsesUtcCutoffInChicago() throws Exception
   {
      var original = java.util.TimeZone.getDefault();
      setting("settle_horizon_seconds", 60);
      try(var connection = owner())
      {
         sql(connection, "ALTER TABLE audit ALTER COLUMN timestamp TYPE timestamp without time zone USING timestamp AT TIME ZONE 'UTC'");
         sql(connection, "INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES"
            + "(1,1,1,TIMESTAMP '2026-10-13 12:00:00'),(2,1,1,TIMESTAMP '2026-10-13 12:01:30')");
         // New runtime connections inherit this non-UTC session setting.
         sql(connection, "ALTER ROLE app SET timezone='America/Chicago'");
         java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("America/Chicago"));
         assertThat(new WormAuditChainer(config).chainOnce(java.time.Instant.parse("2026-10-13T12:02:00Z")).audits()).isEqualTo(1);
         assertThat(STORE.all(WormAuditTables.CHAIN)).extracting(r -> r.getValueLong("audit_id")).containsExactly(1L);
         java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("UTC"));
         assertThat(new WormAuditVerifier(config).verify(java.util.Set.of(1L)).getBreaks()).isEmpty();
      }
      finally
      {
         java.util.TimeZone.setDefault(original);
         try(var connection = owner())
         {
            sql(connection, "ALTER ROLE app RESET timezone");
         }
      }
   }


   /*******************************************************************************
    ** PostgreSQL containment polling includes the lower window boundary only.
    *******************************************************************************/
   @Test
   void postgresLateDetailWindowAndCompleteness() throws Exception
   {
      setting("settle_horizon_seconds", 60);
      var now = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
      var cutoff = now.minusSeconds(60);
      try(var connection = owner(); var statement = connection.prepareStatement(
         "INSERT INTO audit(id,audit_table_id,audit_user_id,timestamp) VALUES(?,1,1,?)"))
      {
         for(int id = 1; id <= 4; id++)
         {
            long seconds = switch(id)
            {
               case 1 -> 86401;
               case 2 -> 86400;
               case 3 -> 1;
               default -> 0;
            };
            statement.setInt(1, id);
            statement.setObject(2, cutoff.minusSeconds(seconds).atOffset(java.time.ZoneOffset.UTC));
            statement.executeUpdate();
         }
      }
      var writer = new WormAuditChainer(config);
      assertThat(writer.chainOnce(now).audits()).isEqualTo(3);
      for(long id = 1; id <= 4; id++)
      {
         detail(id, id);
      }
      assertThat(writer.chainOnce(now).lateDetails()).isEqualTo(2);
      assertThat(STORE.all(WormAuditTables.CHAIN).stream().flatMap(r -> AuditStore.detailIds(r).stream()).toList()).containsExactly(2L, 3L);
      assertThat(new WormAuditVerifier(config).verify().getBreaks()).anyMatch(b -> b.reason().contains("audit_detail 1 is not covered"));
   }


   /*******************************************************************************
    ** Referential integrity guardrail: every table reference of the WORM tables
    ** (possible-value fields, and the chain's audit header) has a RESTRICT
    ** foreign key, or an exemption with its reason. Nothing may cascade into or
    ** out of audit evidence.
    *******************************************************************************/
   @Test
   void everyReferenceHasARestrictForeignKeyOrAReason() throws Exception
   {
      String links = "the retention purge deletes the sealed prefix of chain links; this evidence row outlives the links it names";
      java.util.Map<String, String> exempt = java.util.Map.of(
         "worm_audit_checkpoint.from_link_id", links,
         "worm_audit_checkpoint.to_link_id", links,
         "worm_audit_export.from_link_id", links,
         "worm_audit_export.to_link_id", links,
         "worm_audit_verification.from_link_id", links,
         "worm_audit_verification.to_link_id", links,
         "worm_audit_verification.first_break_link_id", links + "; a break may name a link that is missing",
         "worm_audit_purge.anchor_link_id", "the anchor is the last link the same purge deleted");

      java.util.Set<String> references = new java.util.TreeSet<>(List.of("worm_audit_chain.audit_id"));
      for(var table : instance.getTables().values())
      {
         if(!table.getName().startsWith("worm_audit_"))
         {
            continue;
         }
         for(var field : table.getFields().values())
         {
            if(field.getPossibleValueSourceName() != null && instance.getTable(field.getPossibleValueSourceName()) != null)
            {
               references.add(table.getName() + "." + field.getBackendName());
            }
         }
      }

      java.util.Map<String, String> foreignKeys = new java.util.HashMap<>();
      try(var c = owner(); var s = c.createStatement(); var r = s.executeQuery("""
         SELECT c.conrelid::regclass::text || '.' || a.attname, c.confdeltype::text || c.convalidated::text
         FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
         WHERE c.contype = 'f' AND c.conrelid::regclass::text LIKE 'worm_audit_%'"""))
      {
         while(r.next())
         {
            foreignKeys.put(r.getString(1), r.getString(2));
         }
      }
      assertThat(references.stream().filter(ref -> !foreignKeys.containsKey(ref) && !exempt.containsKey(ref)).toList())
         .as("references without a foreign key (add one to worm-audit.sql, or an exemption with a reason)").isEmpty();
      assertThat(foreignKeys).as("RESTRICT and validated").containsOnlyKeys("worm_audit_chain.audit_id", "worm_audit_export.from_checkpoint_id",
         "worm_audit_export.to_checkpoint_id", "worm_audit_verification.export_id").allSatisfy((k, v) -> assertThat(v).isEqualTo("rtrue"));
   }



   /*******************************************************************************
    ** Upgrading a schema whose chain names a missing audit header: the link is
    ** evidence, so it is copied to qqq_fk_quarantine (KEPT), never changed, and
    ** the constraint is added NOT VALID (new links are still checked). A re-run
    ** changes nothing.
    *******************************************************************************/
   @Test
   void orphanEvidenceIsKeptAndTheConstraintIsNotValidated() throws Exception
   {
      audit(1);
      new WormAuditChainer(config).chainOnce();
      try(var c = owner())
      {
         sql(c, "ALTER TABLE worm_audit_chain DROP CONSTRAINT fk_worm_audit_chain_audit_id");
         sql(c, "ALTER TABLE audit DISABLE TRIGGER worm_audit_row_guard; DELETE FROM audit WHERE id = 1; ALTER TABLE audit ENABLE TRIGGER worm_audit_row_guard");
         sql(c, WormAuditDdl.postgres(config));
         sql(c, WormAuditDdl.postgres(config));
         assertThat(count(c, "SELECT count(*) FROM qqq_fk_quarantine WHERE table_name = 'worm_audit_chain' AND column_name = 'audit_id'"
            + " AND row_id = '1' AND missing_parent_id = '1' AND action = 'KEPT' AND row_data LIKE '%\"link_hash\"%'")).isEqualTo(1);
         assertThat(count(c, "SELECT count(*) FROM qqq_fk_quarantine")).isEqualTo(1);
         assertThat(count(c, "SELECT count(*) FROM worm_audit_chain WHERE id = 1 AND audit_id = 1")).isEqualTo(1);
         assertThat(count(c, "SELECT count(*) FROM pg_constraint WHERE conname = 'fk_worm_audit_chain_audit_id' AND NOT convalidated")).isEqualTo(1);
         assertThatThrownBy(() -> sql(c, "INSERT INTO worm_audit_chain(id,kind,audit_id,detail_ids,prev_hash,link_hash,chained_at)"
            + " VALUES(99,'AUDIT',404,'',repeat('0',64),repeat('0',64),now())"))
            .hasMessageContaining("fk_worm_audit_chain_audit_id");
      }
   }



   /*******************************************************************************
    ** The settings row (seeded by the DDL) overrides config: change it there.
    *******************************************************************************/
   private void setting(String column, int value) throws Exception
   {
      try(var connection = owner())
      {
         sql(connection, "UPDATE worm_audit_settings SET " + column + "=" + value + " WHERE id=1");
      }
      config.invalidateSettings();
   }
}
