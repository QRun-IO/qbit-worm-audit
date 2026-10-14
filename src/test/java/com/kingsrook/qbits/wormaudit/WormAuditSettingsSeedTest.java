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
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** The settings row the shipped database script seeds (ddl/postgres/worm-audit.sql,
 ** changeset worm-audit:10, rendered with the host's configured values).
 ** The whole script is PostgreSQL-only (triggers, roles, plpgsql), so it cannot
 ** run on H2; this runs the settings table's CREATE and its seed statement as
 ** the script renders them, on H2 in PostgreSQL mode: the row appears with the
 ** host's values, a second run inserts nothing, and an edit survives.
 ** WormAuditSettings.seed() is deprecated (nothing in src/main calls it) but still
 ** works for memory and H2 hosts; WormAuditSettings.read() falls back to the
 ** configured values while the row is absent.
 *******************************************************************************/
class WormAuditSettingsSeedTest
{

   /*******************************************************************************
    ** Fresh table, seed twice, edit survives, values follow the host config.
    *******************************************************************************/
   @Test
   void seedStatementIsInsertOnlyAndUsesHostValues() throws Exception
   {
      var config = new WormAuditQBitConfig().withRetentionYears(8).withExportRetentionDays(45).withCheckpointEveryLinks(12);
      String ddl = WormAuditDdl.postgres(config);
      String create = statement(ddl, "CREATE TABLE IF NOT EXISTS public.worm_audit_settings");
      String seed = statement(ddl, "INSERT INTO public.worm_audit_settings");

      try(Connection connection = DriverManager.getConnection("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
         Statement sql = connection.createStatement())
      {
         sql.execute(create.replace("timestamptz", "timestamp with time zone").replace("now()", "CURRENT_TIMESTAMP").replace("current_user", "'app'"));
         sql.execute(seed);
         assertThat(scalar(sql, "SELECT COUNT(*) FROM public.worm_audit_settings")).isEqualTo("1");
         assertThat(scalar(sql, "SELECT audit_retention_years FROM public.worm_audit_settings")).isEqualTo("8");
         assertThat(scalar(sql, "SELECT export_retention_days FROM public.worm_audit_settings")).isEqualTo("45");
         assertThat(scalar(sql, "SELECT checkpoint_every_links FROM public.worm_audit_settings")).isEqualTo("12");
         assertThat(scalar(sql, "SELECT export_lock_mode FROM public.worm_audit_settings")).isEqualTo(config.getExportLockMode());
         assertThat(scalar(sql, "SELECT export_cron FROM public.worm_audit_settings")).isEqualTo(config.getExportCron());

         sql.execute("UPDATE public.worm_audit_settings SET export_retention_days = 90 WHERE id = 1");
         sql.execute(seed);
         assertThat(scalar(sql, "SELECT COUNT(*) FROM public.worm_audit_settings")).isEqualTo("1");
         assertThat(scalar(sql, "SELECT export_retention_days FROM public.worm_audit_settings")).isEqualTo("90");
      }
   }



   /*******************************************************************************
    ** The deprecated public seed() still creates row 1 once and keeps edits.
    *******************************************************************************/
   @Test
   @SuppressWarnings("deprecation")
   void deprecatedSeedStillWorksForMemoryHosts() throws Exception
   {
      var config = new WormAuditQBitConfig().withRetentionYears(8);
      WormAuditTestSupport.init(config);
      WormAuditSettings.seed(config);
      assertThat(WormAuditTestSupport.STORE.get("worm_audit_settings", 1).getValueInteger("audit_retention_years")).isEqualTo(8);
      WormAuditSettings.seed(config);
      assertThat(WormAuditTestSupport.STORE.get("worm_audit_settings", 1)).isNotNull();
   }



   /*******************************************************************************
    ** The script seeds nothing but the settings table: its only top-level INSERT is the
 ** settings seed (the indented purge INSERTs are the purge function writing its log).
    *******************************************************************************/
   @Test
   void onlySettingsAreSeeded()
   {
      String ddl = WormAuditDdl.postgres(new WormAuditQBitConfig());
      Matcher matcher = Pattern.compile("(?m)^INSERT INTO\\s+(\\S+)").matcher(ddl);
      while(matcher.find())
      {
         assertThat(matcher.group(1)).as("every top-level INSERT in the script targets the settings table, not a log").isEqualTo("public.worm_audit_settings");
      }
   }



   /*******************************************************************************
    ** From the start text up to the statement's closing semicolon.
    *******************************************************************************/
   private static String statement(String ddl, String start)
   {
      int from = ddl.indexOf(start);
      assertThat(from).as(start).isGreaterThanOrEqualTo(0);
      return (ddl.substring(from, ddl.indexOf(";", from)));
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String scalar(Statement sql, String query) throws Exception
   {
      try(ResultSet result = sql.executeQuery(query))
      {
         assertThat(result.next()).isTrue();
         return (result.getString(1));
      }
   }

}
