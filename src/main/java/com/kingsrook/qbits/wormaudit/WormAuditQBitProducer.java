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


import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qbits.wormaudit.model.LinkRangeWidget;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppSection;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaDataProducer;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.quartz.QuartzSchedulerMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Produces append-only audit metadata, verification actions and schedules.
 *******************************************************************************/
public class WormAuditQBitProducer implements QBitMetaDataProducer<WormAuditQBitConfig>
{
   public static final String GROUP_ID    = "com.kingsrook.qbits";
   public static final String ARTIFACT_ID = "qbit-worm-audit";
   public static final String VERSION     = "0.1.0";

   private WormAuditQBitConfig qBitConfig;
   private String namespace;



   /*******************************************************************************
    ** Fluent setter for the config.
    *******************************************************************************/
   public WormAuditQBitProducer withQBitConfig(WormAuditQBitConfig config)
   {
      this.qBitConfig = config;
      return (this);
   }



   /*******************************************************************************
    ** Getter for the config.
    *******************************************************************************/
   @Override
   public WormAuditQBitConfig getQBitConfig()
   {
      return (qBitConfig);
   }



   /*******************************************************************************
    ** Fluent setter for the namespace.
    *******************************************************************************/
   public WormAuditQBitProducer withNamespace(String namespace)
   {
      this.namespace = namespace;
      return (this);
   }



   /*******************************************************************************
    ** Getter for the namespace.
    *******************************************************************************/
   @Override
   public String getNamespace()
   {
      return (namespace);
   }



   /*******************************************************************************
    ** Identity and configuration of this qbit.
    *******************************************************************************/
   @Override
   public QBitMetaData getQBitMetaData()
   {
      return (new QBitMetaData().withGroupId(GROUP_ID).withArtifactId(ARTIFACT_ID).withVersion(VERSION).withNamespace(namespace).withConfig(qBitConfig));
   }



   /*******************************************************************************
    ** Package-scanned producers have no config: skip them.
    *******************************************************************************/
   @Override
   public boolean isEnabled()
   {
      return (qBitConfig != null);
   }



   /*******************************************************************************
    ** Register phase (a) tables, processes and schedules on the host backend.
    *******************************************************************************/
   @Override
   public MetaDataProducerMultiOutput produce(QInstance qInstance) throws QException
   {
      qBitConfig.validate();
      if(qInstance.getBackend(qBitConfig.getBackendName()) == null)
      {
         throw (new IllegalArgumentException("Configured audit backend is missing"));
      }
      WormAuditDdl.resolveNames(qBitConfig, qInstance);
      for(String core : AppendOnlyGuard.CORE_TABLES)
      {
         if(!qBitConfig.getBackendName().equals(qInstance.getTable(core).getBackendName()))
         {
            throw (new IllegalArgumentException("Core and WORM audit tables must share one backend"));
         }
      }
      QBitMetaData qBit = getQBitMetaData();
      MetaDataProducerMultiOutput output = new MetaDataProducerMultiOutput().with(qBit);
      AppendOnlyGuard guard = new AppendOnlyGuard();
      for(QTableMetaData table : WormAuditTables.tables(qBitConfig))
      {
         if(qBitConfig.getTableMetaDataCustomizer() != null)
         {
            table = qBitConfig.getTableMetaDataCustomizer().customizeMetaData(qInstance, table);
         }
         guard.customizeMetaData(qInstance, table);
         table.setSourceQBitName(qBit.getName());
         output.add(table);
      }
      for(String core : AppendOnlyGuard.CORE_TABLES)
      {
         guard.customizeMetaData(qInstance, qInstance.getTable(core));
      }
      for(String name : WormAuditTables.ALL)
      {
         output.add(QPossibleValueSource.newForTable(name));
      }
      for(String name : java.util.List.of(WormAuditTables.CHECKPOINT, WormAuditTables.EXPORT, WormAuditTables.VERIFICATION))
      {
         output.add(new QWidgetMetaData().withName(name + "_links").withLabel("Chain links").withType("childRecordList")
            .withCodeReference(new QCodeReference(LinkRangeWidget.class)).withDefaultValue("parentTable", name));
      }
      for(var process : WormAuditProcesses.processes(qBitConfig))
      {
         process.setSourceQBitName(qBit.getName());
         output.add(process);
      }
      if(qInstance.getSchedulers() == null || !qInstance.getSchedulers().containsKey(qBitConfig.getSchedulerName()))
      {
         qInstance.addScheduler(new QuartzSchedulerMetaData().withName(qBitConfig.getSchedulerName()));
      }
      QAppMetaData app = new QAppMetaData().withName("worm_audit").withLabel("WORM Audit").withIcon(new QIcon("policy"));
      for(String name : WormAuditTables.NAV)
      {
         QTableMetaData table = output.getEach(QTableMetaData.class).stream().filter(t -> t.getName().equals(name)).findFirst().orElseThrow();
         app.withSectionOfChildren(new QAppSection().withName(name).withLabel(table.getLabel()), table);
      }
      output.add(app);
      // RC.5 rejects underscores in declared alert type names. QAlerts still
      // dispatches the specified worm_audit.chain.break signal to installed sinks.
      output.addSelfToInstance(qInstance);
      denyAssistant(qInstance);
      return (new MetaDataProducerMultiOutput());
   }


   /*******************************************************************************
    ** RC.5 compatibility: replace with a direct call when the qbit builds on RC.6 (qqq#1141, #1163).
    *******************************************************************************/
   private void denyAssistant(QInstance instance) throws QException
   {
      try
      {
         Class<?> type = Class.forName("com.kingsrook.qqq.backend.core.model.metadata.permissions.ClientChannelsMetaData");
         Object metadata = type.getMethod("ofOrWithNew", QInstance.class).invoke(null, instance);
         type.getMethod("withDeniedPattern", String.class, String.class).invoke(metadata, "assistant", "worm_audit_*");
      }
      catch(ClassNotFoundException expected)
      {
         // The assistant wall API is absent in RC.5.
      }
      catch(ReflectiveOperationException e)
      {
         throw (new QException("Cannot register the WORM audit assistant deny pattern", e));
      }
   }
}
