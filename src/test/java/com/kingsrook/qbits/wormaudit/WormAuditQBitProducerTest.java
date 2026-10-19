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

import java.util.List;
import com.kingsrook.qbits.wormaudit.app.WormAuditApp;
import com.kingsrook.qbits.wormaudit.model.WormAuditHelp;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Tests and fixtures for worm audit qbit producer test.
 *******************************************************************************/
class WormAuditQBitProducerTest
{
   /*******************************************************************************
    ** Verify metadata and defaults.
    *******************************************************************************/
   @Test
   void metadataAndDefaults() throws Exception
   {
      var config = new WormAuditQBitConfig();
      QInstance instance = WormAuditTestSupport.init(config);
      assertThat(config.getIncludeApp()).isTrue();
      assertThat(config.getRetentionYears()).isEqualTo(6);
      assertThat(config.getTableMetaDataCustomizer()).isNull();
      assertThat(config.getSigningKey()).isNull();
      assertThat(config.getTrustedPublicKeys()).isEmpty();
      assertThat(config.getChainIntervalSeconds()).isEqualTo(30);
      assertThat(config.getSettleHorizonSeconds()).isEqualTo(60);
      assertThat(config.getCheckpointEveryLinks()).isEqualTo(10000);
      assertThat(config.getCheckpointEveryMinutes()).isEqualTo(60);
      assertThat(config.getBatchSize()).isEqualTo(1000);
      assertThat(config.getLateDetailLookbackHours()).isEqualTo(24);
      assertThat(config.getVerifyCron()).isEqualTo("0 0 3 * * ?");
      assertThat(config.getAppRole()).isEqualTo("app");
      assertThat(instance.getQBits().get("com.kingsrook.qbits:qbit-worm-audit").getConfig())
            .isSameAs(config);
      assertThat(instance.getApp("worm_audit").getSections())
            .extracting(s -> s.getName())
            .containsExactlyElementsOf(WormAuditTables.NAV);
      assertThat(instance.getApp("worm_audit").getChildren())
            .allMatch(
                  c ->
                        c.getName().startsWith("worm_audit_")
                              && !c.getName().contains("verify"));
      assertThat(instance.getProcess(WormAuditProcesses.VERIFY).getTableName())
            .isEqualTo(WormAuditTables.CHAIN);
      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds())
            .isEqualTo(30);
      assertThat(instance.getProcess(WormAuditProcesses.DAILY).getSchedule().getCronExpression())
            .isEqualTo(config.getVerifyCron());
      for(String name :
            List.of(
                  "audit",
                  "auditDetail",
                  "auditUser",
                  "auditTable",
                  WormAuditTables.CHAIN,
                  WormAuditTables.CHECKPOINT,
                  WormAuditTables.EXPORT,
                  WormAuditTables.VERIFICATION,
                  WormAuditTables.PURGE))
      {
         var table = instance.getTable(name);
         assertThat(
                     table.isCapabilityEnabled(
                           instance.getBackendForTable(name), Capability.TABLE_UPDATE))
               .isFalse();
         assertThat(
                     table.isCapabilityEnabled(
                           instance.getBackendForTable(name), Capability.TABLE_DELETE))
               .isFalse();
         if(name.startsWith("worm_audit_"))
         {
            assertThat(table.getPermissionRules().getPermissionBaseName()).isEqualTo(name);
            assertThat(
                        table.isCapabilityEnabled(
                              instance.getBackendForTable(name), Capability.TABLE_INSERT))
                  .isFalse();
            assertThat(table.getSections()).isNotEmpty();
         }
      }
   }

   /*******************************************************************************
    ** Verify customizations and validation.
    *******************************************************************************/
   @Test
   void customizationsAndValidation() throws Exception
   {
      assertThat(new WormAuditQBitProducer().isEnabled()).isFalse();
      var config =
            new WormAuditQBitConfig()
                  .withRetentionYears(7)
                  .withChainIntervalSeconds(45)
                  .withSettleHorizonSeconds(0)
                  .withBatchSize(13)
                  .withCheckpointEveryLinks(5)
                  .withCheckpointEveryMinutes(2)
                  .withVerifyCron("0 1 3 * * ?")
                  .withAppRole("runtime")
                  .withSchedulerName("jobs")
                  .withCoreAuditTableNames(java.util.Map.of("audit", "custom_audit"))
                  .withTableMetaDataCustomizer(
                        (instance, table) ->
                              table.withLabel("custom")
                                    .withCapabilities(Capability.TABLE_UPDATE));
      var instance =
            WormAuditTestSupport.core(
                  new com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData()
                        .withName("memory")
                        .withBackendType(
                              com.kingsrook.qqq.backend.core.modules.backend
                                    .implementations.memory.MemoryBackendModule.class));
      var producer =
            new WormAuditQBitProducer()
                  .withNamespace("test")
                  .withQBitConfig(config.withBackendName("memory"));
      producer.produce(instance);
      assertThat(producer.getNamespace()).isEqualTo("test");
      assertThat(producer.getQBitConfig()).isSameAs(config);
      assertThat(producer.isEnabled()).isTrue();
      assertThat(config.getCoreAuditTableNames()).containsEntry("audit", "custom_audit");
      assertThat(instance.getTable(WormAuditTables.CHAIN).getLabel()).isEqualTo("custom");
      assertThat(
                  instance.getTable(WormAuditTables.CHAIN)
                        .isCapabilityEnabled(
                              instance.getBackend("memory"), Capability.TABLE_UPDATE))
            .isFalse();
      assertThatThrownBy(() -> new WormAuditQBitConfig().validate())
            .isInstanceOf(IllegalArgumentException.class);
      assertThat(config.withLateDetailLookbackHours(48).getLateDetailLookbackHours()).isEqualTo(48);
      assertThatThrownBy(() -> config.withLateDetailLookbackHours(0).validate()).isInstanceOf(IllegalArgumentException.class);
      config.withLateDetailLookbackHours(24);
      assertThatThrownBy(() -> config.withRetentionYears(0).validate())
            .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(
                  () -> WormAuditDdl.resolveNames(new WormAuditQBitConfig(), new QInstance()))
            .isInstanceOf(IllegalArgumentException.class);
   }


   /*******************************************************************************
    ** Embedded production keeps the host app intact and registers all evidence metadata.
    *******************************************************************************/
   @Test
   void embeddedMetadataPreservesHostApp() throws Exception
   {
      var config = new WormAuditQBitConfig().withBackendName("memory").withIncludeApp(false).withAppName("audit");
      var instance = WormAuditTestSupport.core(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
      var host = new QAppMetaData().withName("audit").withLabel("Combined Audit").withWidgets(List.of("hostSummary"));
      instance.addApp(host);
      new WormAuditQBitProducer().withQBitConfig(config).produce(instance);
      assertThat(config.getIncludeApp()).isFalse();
      assertThat(instance.getApp("worm_audit")).isNull();
      assertThat(instance.getApp("audit")).isSameAs(host);
      assertThat(host.getLabel()).isEqualTo("Combined Audit");
      assertThat(host.getWidgets()).containsExactly("hostSummary");
      assertThat(host.getHelpContent()).isNullOrEmpty();
      assertThat(instance.getWidget(WormAuditApp.HEALTH_CARD_WIDGET)).isNotNull();
      assertThat(instance.getWidget(WormAuditApp.HOME_WIDGET)).isNotNull();
      for(String name : WormAuditTables.ALL)
      {
         assertThat(instance.getTable(name).getHelpContent()).containsKey(WormAuditHelp.SLOT);
         assertThat(instance.getTable(name).getPermissionRules().getPermissionBaseName()).isEqualTo(name);
      }
      assertThat(instance.getTable(WormAuditTables.CHAIN).getDisabledCapabilities()).contains(Capability.TABLE_UPDATE, Capability.TABLE_DELETE, Capability.TABLE_INSERT);
      assertThat(instance.getTable("audit").getDisabledCapabilities()).contains(Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      assertThat(instance.getProcess(WormAuditProcesses.VERIFY)).isNotNull();
      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds()).isEqualTo(config.getChainIntervalSeconds());
      assertThat(instance.getProcess(WormAuditProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo(config.getVerifyCron());
   }
}
