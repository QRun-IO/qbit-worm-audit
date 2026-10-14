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


import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.wormaudit.app.WormAuditHomeData;
import com.kingsrook.qbits.wormaudit.app.WormAuditHomeView;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.export.SealedExportVerifier;
import com.kingsrook.qbits.wormaudit.model.SettingsCustomizer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qbits.wormaudit.processes.ExportProcesses;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.UpdateAction;
import com.kingsrook.qqq.backend.core.actions.tables.DeleteAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.*;
import static org.assertj.core.api.Assertions.*;


/*******************************************************************************
 ** Editable settings, bounded cache, audited changes and historical lock modes.
 *******************************************************************************/
class WormAuditSettingsTest
{
   static final String TABLE = WormAuditTables.SETTINGS;

   /*******************************************************************************
    ** Deterministic clock for the exact 30-second cache boundary.
    *******************************************************************************/
   static class MutableClock extends Clock
   {
      Instant now = Instant.parse("2026-10-14T02:00:00Z");
      /*******************************************************************************
       ** Verify get zone.
       *******************************************************************************/
      public ZoneId getZone()
      {
         return (ZoneOffset.UTC);
      }
      /*******************************************************************************
       ** Verify with zone.
       *******************************************************************************/
      public Clock withZone(ZoneId zone)
      {
         return (this);
      }
      /*******************************************************************************
       ** Verify instant.
       *******************************************************************************/
      public Instant instant()
      {
         return (now);
      }
   }

   /*******************************************************************************
    ** Verify editor.
    *******************************************************************************/
   static void editor()
   {
      QContext.getQInstance().withEnforcePermissionsInCoreActions(true);
      QContext.getQSession().withPermissions(Set.of(TABLE + ".read", TABLE + ".edit", "worm_audit.settings"));
   }

   /*******************************************************************************
    ** Verify update.
    *******************************************************************************/
   static void update(String field, java.io.Serializable value) throws Exception
   {
      var result = new UpdateAction().execute(new UpdateInput(TABLE).withRecords(List.of(new QRecord().withValue("id", 1).withValue(field, value))));
      assertThat(result.getRecords()).allSatisfy(row -> assertThat(row.getErrors()).isNullOrEmpty());
   }

   /*******************************************************************************
    ** Verify fallback overrides cache and insert only seed.
    *******************************************************************************/
   @Test
   void fallbackOverridesCacheAndInsertOnlySeed() throws Exception
   {
      var config = new WormAuditQBitConfig().withRetentionYears(8).withExportRetentionDays(45).withCheckpointEveryLinks(12);
      var instance = init(config);
      var clock = new MutableClock();
      var reader = new WormAuditSettings(config, clock);
      assertThat(reader.read().audit_retention_years()).isEqualTo(8);
      assertThat(reader.read().export_retention_days()).isEqualTo(45);
      WormAuditTestSupport.seedSettings(config);
      editor();
      update("export_retention_days", 90);
      assertThat(reader.read().export_retention_days()).isEqualTo(90);
      update("export_retention_days", 120);
      clock.now = clock.now.plusSeconds(29);
      assertThat(reader.read().export_retention_days()).isEqualTo(90);
      clock.now = clock.now.plusSeconds(1);
      assertThat(reader.read().export_retention_days()).isEqualTo(120);
      WormAuditTestSupport.seedSettings(config);
      assertThat(STORE.get(TABLE, 1).getValueInteger("export_retention_days")).isEqualTo(120);
      assertThat(reader.read().checkpoint_every_links()).isEqualTo(12);
      instance.getTables().remove(TABLE);
      reader.invalidate();
      assertThat(reader.read().export_retention_days()).isEqualTo(45);
   }

   /*******************************************************************************
    ** Verify partial null row uses config and invalid persisted settings fail closed.
    *******************************************************************************/
   @Test
   void partialNullRowUsesConfigAndInvalidPersistedSettingsFailClosed() throws Exception
   {
      var config = new WormAuditQBitConfig().withExportRetentionDays(42);
      init(config);
      com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore.getInstance().insert(
         new InsertInput(TABLE).withRecord(new QRecord().withValue("id", 1).withValue("export_lock_mode", "COMPLIANCE")), false);
      var reader = new WormAuditSettings(config);
      assertThat(reader.read().export_retention_days()).isEqualTo(42);
      assertThat(reader.read().export_lock_mode()).isEqualTo("COMPLIANCE");
      com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore.getInstance().update(
         new UpdateInput(TABLE).withRecords(List.of(new QRecord().withValue("id", 1).withValue("export_retention_days", 0))), false);
      reader.invalidate();
      assertThatThrownBy(reader::read).hasMessageContaining("Export retention days");
   }

   /*******************************************************************************
    ** Verify missing physical table falls back.
    *******************************************************************************/
   @Test
   void missingPhysicalTableFallsBack() throws Exception
   {
      var config = new WormAuditQBitConfig().withExportRetentionDays(81);
      var instance = RdbmsTestSupport.instance("jdbc:h2:mem:settings_missing;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE", "sa", "", config, false);
      QContext.init(instance, new QSession());
      assertThat(config.effectiveSettings().export_retention_days()).isEqualTo(81);
   }

   /*******************************************************************************
    ** Verify validation and capabilities.
    *******************************************************************************/
   @Test
   void validationAndCapabilities() throws Exception
   {
      var config = new WormAuditQBitConfig();
      var instance = init(config);
      var table = instance.getTable(TABLE);
      assertThat(table.getLabel()).isEqualTo("WORM Audit Settings");
      assertThat(table.getAuditRules().getAuditLevel()).isEqualTo(AuditLevel.FIELD);
      assertThat(table.isCapabilityEnabled(instance.getBackendForTable(TABLE), Capability.TABLE_UPDATE)).isTrue();
      assertThat(table.isCapabilityEnabled(instance.getBackendForTable(TABLE), Capability.TABLE_INSERT)).isFalse();
      assertThat(table.isCapabilityEnabled(instance.getBackendForTable(TABLE), Capability.TABLE_DELETE)).isFalse();
      WormAuditTestSupport.seedSettings(config);
      editor();
      assertThatThrownBy(() -> new DeleteAction().execute(new DeleteInput(TABLE).withPrimaryKeys(List.of(1)))).isInstanceOf(Exception.class);
      assertThatThrownBy(() -> new InsertAction().execute(new InsertInput(TABLE).withRecord(new QRecord().withValue("id", 2)))).isInstanceOf(Exception.class);
      assertThatThrownBy(() -> new SettingsCustomizer().preInsert(new InsertInput(TABLE), List.of(new QRecord().withValue("id", 2)), false)).hasMessageContaining("one row only (ID 1)");
      assertThatThrownBy(() -> new SettingsCustomizer().preInsert(new InsertInput(TABLE), List.of(WormAuditSettings.defaults(config)), false))
         .hasMessageContaining("already exists");
      assertThatThrownBy(() -> new SettingsCustomizer().preDelete(new DeleteInput(TABLE), List.of(STORE.get(TABLE, 1)), false))
         .hasMessageContaining("cannot be deleted");
      for(String field : List.of("audit_retention_years", "export_retention_days", "checkpoint_every_links", "checkpoint_every_minutes", "chain_interval_seconds", "late_detail_lookback_hours"))
      {
         assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue(field, 0))).hasMessageContaining("whole number");
      }
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("settle_horizon_seconds", -1))).hasMessageContaining("Settle horizon seconds");
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("audit_retention_years", 101))).hasMessageContaining("100");
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("export_retention_days", 36501))).hasMessageContaining("36500");
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("export_retention_days", "1.5"))).hasMessageContaining("whole number");
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("export_lock_mode", "NONE"))).hasMessageContaining("GOVERNANCE or COMPLIANCE");
      assertThatThrownBy(() -> WormAuditSettings.validate(new QRecord().withValue("export_lock_mode", null))).hasMessageContaining("GOVERNANCE or COMPLIANCE");
      for(String field : List.of("export_cron", "verify_cron"))
      {
         assertThatThrownBy(() -> new SettingsCustomizer().preUpdate(new UpdateInput(TABLE), List.of(new QRecord().withValue("id", 1).withValue(field, "bad")), false, java.util.Optional.empty()))
            .hasMessageContaining("valid Quartz cron");
      }
      assertThatThrownBy(() -> new UpdateAction().execute(new UpdateInput(TABLE).withRecords(List.of(new QRecord().withValue("id", 1).withValue("export_cron", "bad")))))
         .hasMessageContaining("valid Quartz cron");
      assertThat(STORE.get(TABLE, 1).getValueString("export_cron")).isEqualTo(config.getExportCron());
   }

   /*******************************************************************************
    ** Verify edit requires both permissions and produces field audit that chains.
    *******************************************************************************/
   @Test
   void editRequiresBothPermissionsAndProducesFieldAuditThatChains() throws Exception
   {
      var config = ChainVerificationTest.signed().withSettleHorizonSeconds(0);
      init(config);
      WormAuditTestSupport.seedSettings(config);
      QContext.getQInstance().withEnforcePermissionsInCoreActions(true);
      QContext.getQSession().withPermissions(Set.of(TABLE + ".read", TABLE + ".edit"));
      assertThatThrownBy(() -> update("export_lock_mode", "COMPLIANCE")).hasMessageContaining("worm_audit.settings");
      QContext.getQSession().setPermissions(new java.util.HashSet<>(Set.of("worm_audit.settings")));
      assertThatThrownBy(() -> update("export_lock_mode", "COMPLIANCE")).hasMessageContaining("worm_audit_settings.edit");
      editor();
      update("export_lock_mode", "COMPLIANCE");
      assertThat(STORE.all("audit")).hasSize(1);
      assertThat(STORE.where("auditDetail", "fieldName", "export_lock_mode")).hasSize(1);
      assertThat(STORE.get(TABLE, 1).getValueInstant("modify_date")).isNotNull();
      assertThat(STORE.get(TABLE, 1).getValueString("modified_by")).isEqualTo("system");
      new WormAuditChainer(config).chainOnce(Instant.now().plusSeconds(1));
      assertThat(STORE.all(WormAuditTables.CHAIN)).hasSize(1);
      assertThat(new WormAuditVerifier(config).verify(null, Instant.now().plusSeconds(1)).passed()).isTrue();
   }

   /*******************************************************************************
    ** Verify startup schedules and home use effective settings.
    *******************************************************************************/
   @Test
   void startupSchedulesAndHomeUseEffectiveSettings() throws Exception
   {
      var config = ChainVerificationTest.signed();
      var instance = init(config);
      WormAuditTestSupport.seedSettings(config);
      editor();
      update("chain_interval_seconds", 45);
      update("export_cron", "0 15 4 * * ?");
      update("verify_cron", "0 30 5 * * ?");
      update("audit_retention_years", 7);
      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds()).isEqualTo(30);
      var restarted = WormAuditTestSupport.core(new com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData().withName("memory")
         .withBackendType(com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule.class));
      new WormAuditQBitProducer().withQBitConfig(config).produce(restarted);
      assertThat(QContext.getQInstance()).isSameAs(instance);
      instance = restarted;
      QContext.init(instance, new QSession());
      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds()).isEqualTo(45);
      assertThat(instance.getProcess(ExportProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo("0 15 4 * * ?");
      assertThat(instance.getProcess(WormAuditProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo("0 30 5 * * ?");
      assertThat(instance.getProcess(WormAuditProcesses.DAILY).getSchedule().getCronTimeZoneId()).isEqualTo("UTC");
      audit(50);
      var home = WormAuditHomeData.load(config, new SealedExportTest.MemorySealedStore(), Instant.now());
      assertThat(home.nextPurge()).isEqualTo(OLD.plusSeconds(50).atZone(ZoneOffset.UTC).plusYears(7).toInstant());
      assertThat(home.warnings()).anyMatch(w -> w.contains("differs from") && w.contains("purge interval"));
      assertThat(WormAuditHomeView.render(home, "/app")).contains("GOVERNANCE", "s3:BypassGovernanceRetention", "Switch to COMPLIANCE", "30 days", "Export retention is shorter");
   }

   /*******************************************************************************
    ** Verify switch affects new exports only and old checkpoint cadence remains valid.
    *******************************************************************************/
   @Test
   void switchAffectsNewExportsOnlyAndOldCheckpointCadenceRemainsValid() throws Exception
   {
      var config = ChainVerificationTest.signed().withCheckpointEveryLinks(2).withSettleHorizonSeconds(0);
      init(config);
      WormAuditTestSupport.seedSettings(config);
      var storage = new SealedExportTest.MemorySealedStore();
      audit(1);
      audit(2);
      Instant now = Instant.now().plusSeconds(1);
      new WormAuditChainer(config).chainOnce(now);
      var exporter = new SealedExporter(config, storage);
      var first = exporter.run("USER", now).row();
      assertThat(first).isNotNull();
      assertThat(first.getValueString("lock_mode")).isEqualTo("GOVERNANCE");
      assertThat(first.getValueInstant("retain_until")).isEqualTo(now.truncatedTo(java.time.temporal.ChronoUnit.MILLIS).plusSeconds(30 * 86400L));
      assertThat(storage.heads.values()).allSatisfy(h -> assertThat(h.getLockMode()).isEqualTo("GOVERNANCE"));
      var verifier = new SealedExportVerifier(config, storage);
      assertThat(verifier.verify(first, "USER").result().passed()).isTrue();
      editor();
      update("export_lock_mode", "COMPLIANCE");
      update("checkpoint_every_links", 1);
      new WormAuditChainer(config).chainOnce(Instant.now().plusSeconds(2));
      var second = exporter.run("USER", Instant.now().plusSeconds(2)).row();
      assertThat(second.getValueString("lock_mode")).isEqualTo("COMPLIANCE");
      assertThat(verifier.verify(first, "USER").result().passed()).isTrue();
      assertThat(verifier.verify(second, "USER").result().passed()).isTrue();
      assertThat(new WormAuditVerifier(config).verify(null, Instant.now().plusSeconds(2)).passed()).isTrue();
      String key = first.getValueString("object_prefix") + "links.jsonl";
      storage.heads.get(key).withLockMode("COMPLIANCE");
      assertThat(verifier.verify(first, "USER").result().getBreaks()).anyMatch(b -> b.reason().contains("lacks the recorded GOVERNANCE retention"));
      storage.heads.remove(key);
      assertThat(verifier.verify(first, "USER").result().getBreaks()).anyMatch(b -> b.reason().contains(key) && b.reason().contains("GOVERNANCE bypass removal"));
   }
}
