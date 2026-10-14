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
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.ExportProcesses;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Regression: production must work on a host whose default authentication
 ** rejects tokenless sessions (kof22 uses OAuth2). produce() reads the settings
 ** singleton for the startup schedules; under a plain new QSession() that read
 ** failed with "The token is null" and the host could not start.
 *******************************************************************************/
class TokenRequiredHostTest
{
   /*******************************************************************************
    ** Clear the context and the memory store.
    *******************************************************************************/
   @AfterEach
   void tearDown()
   {
      MemoryRecordStore.fullReset();
      QContext.clear();
   }



   /*******************************************************************************
    ** The test module really rejects a tokenless session, so the tests below
    ** prove the qbit does not use one.
    *******************************************************************************/
   @Test
   void moduleRejectsTokenlessSession() throws Exception
   {
      MemoryRecordStore.fullReset();
      QInstance instance = tokenRequiredHost(new WormAuditQBitConfig());
      QContext.init(instance, new QSession());
      assertThatThrownBy(() -> new AuditStore(null).get(WormAuditTables.SETTINGS, 1))
         .hasStackTraceContaining("The token is null");
   }



   /*******************************************************************************
    ** produce() succeeds and still honors the persisted settings row for the
    ** startup schedules, read as the system user.
    *******************************************************************************/
   @Test
   void produceReadsPersistedSettingsAsSystemUser() throws Exception
   {
      ////////////////////////////////////////////////////////////////////
      // first start: an anonymous host stores an edited settings row //
      ////////////////////////////////////////////////////////////////////
      MemoryRecordStore.fullReset();
      WormAuditQBitConfig seedConfig = new WormAuditQBitConfig();
      QInstance seedHost = WormAuditTestSupport.core(memory());
      new WormAuditQBitProducer().withQBitConfig(seedConfig.withBackendName("memory")).produce(seedHost);
      QContext.init(seedHost, new QSession());
      QRecord row = WormAuditSettings.defaults(seedConfig)
         .withValue("chain_interval_seconds", 45)
         .withValue("verify_cron", "0 15 4 * * ?")
         .withValue("export_cron", "0 45 1 * * ?");
      new AuditStore(null).insert(WormAuditTables.SETTINGS, List.of(row));
      QContext.clear();

      //////////////////////////////////////////////////////////////////////
      // restart on a token-required host, with no session in context, as //
      // when a host builds its instance before any request arrives       //
      //////////////////////////////////////////////////////////////////////
      QInstance instance = tokenRequiredHost(new WormAuditQBitConfig());

      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds()).isEqualTo(45);
      assertThat(instance.getProcess(WormAuditProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo("0 15 4 * * ?");
      assertThat(instance.getProcess(ExportProcesses.DAILY).getSchedule().getCronExpression()).isEqualTo("0 45 1 * * ?");
      assertThat(QContext.getQSession()).isNull();
   }



   /*******************************************************************************
    ** With no settings row, production falls back to the configured values.
    *******************************************************************************/
   @Test
   void produceFallsBackToConfigWithoutRow() throws Exception
   {
      MemoryRecordStore.fullReset();
      QInstance instance = tokenRequiredHost(new WormAuditQBitConfig().withChainIntervalSeconds(17));
      assertThat(instance.getProcess(WormAuditProcesses.CHAIN).getSchedule().getRepeatSeconds()).isEqualTo(17);
   }



   /*******************************************************************************
    ** Build a host whose default authentication requires a token, and produce.
    *******************************************************************************/
   private static QInstance tokenRequiredHost(WormAuditQBitConfig config) throws Exception
   {
      QInstance instance = WormAuditTestSupport.core(memory());
      instance.withInstanceDefaultAuthentication(new QAuthenticationMetaData()
         .withName("token-required")
         .withType(QAuthenticationType.MOCK)
         .withModuleCodeReference(new QCodeReference(TokenRequiredAuthenticationModule.class)));
      new WormAuditQBitProducer().withQBitConfig(config.withBackendName("memory")).produce(instance);
      return (instance);
   }



   /*******************************************************************************
    ** The memory backend.
    *******************************************************************************/
   private static QBackendMetaData memory()
   {
      return (new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
   }
}
