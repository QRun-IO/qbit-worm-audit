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
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qbits.wormaudit.model.LinkRangeWidget;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.ExportProcesses;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qqq.backend.core.alerts.AlertDefaultMonitor;
import com.kingsrook.qqq.backend.core.alerts.AlertSeverity;
import com.kingsrook.qqq.backend.core.alerts.QAlertTypeMetaData;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
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
    ** Register audit tables, verification/export actions and schedules.
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
         for(var field : table.getFields().values())
         {
            if(field.getInlinePossibleValueSource() != null)
            {
               output.add(field.getInlinePossibleValueSource());
               field.withPossibleValueSourceName(field.getInlinePossibleValueSource().getName()).withInlinePossibleValueSource(null);
            }
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
         QPossibleValueSource source = QPossibleValueSource.newForTable(name);
         if(WormAuditTables.CHAIN.equals(name))
         {
            source.withValueFormat("%s").withValueFields(java.util.List.of("id"));
         }
         output.add(source);
      }
      for(String name : java.util.List.of(WormAuditTables.CHECKPOINT, WormAuditTables.EXPORT, WormAuditTables.VERIFICATION))
      {
         output.add(new QWidgetMetaData().withName(name + "_links").withLabel("Chain links").withType("childRecordList").withGridColumns(12)
            .withCodeReference(new QCodeReference(LinkRangeWidget.class)).withDefaultValue("parentTable", name));
      }
      List<QTableMetaData> producedTables = output.getEach(QTableMetaData.class);
      output.addSelfToInstance(qInstance);
      output = new MetaDataProducerMultiOutput();
      var previousInstance = QContext.getQInstance();
      var previousSession = QContext.getQSession();
      var previousTransaction = QContext.getQBackendTransaction();
      try
      {
         // Production is still assembling the host metadata. Do not validate it mid-build.
         QContext.setQInstance(qInstance);
         QContext.setQSession(new com.kingsrook.qqq.backend.core.model.session.QSession());
         QContext.setTransaction(null);
         addProcesses(output, qBit);
      }
      finally
      {
         QContext.setQInstance(previousInstance);
         QContext.setQSession(previousSession);
         QContext.setTransaction(previousTransaction);
      }
      if(qInstance.getSchedulers() == null || !qInstance.getSchedulers().containsKey(qBitConfig.getSchedulerName()))
      {
         qInstance.addScheduler(new QuartzSchedulerMetaData().withName(qBitConfig.getSchedulerName()));
      }
      output.add(WormAuditApp.app(qBitConfig, producedTables));
      for(QWidgetMetaData widget : WormAuditApp.widgets())
      {
         output.add(widget);
      }
      output.add(new QAlertTypeMetaData().withName("wormaudit.chain.break").withLabel("Audit chain break")
         .withSourceQBitName(qBit.getName()).withDefaultSeverity(AlertSeverity.CRITICAL)
         .withDescription("Audit chain verification found a break in content, continuity, coverage or checkpoint trust.")
         .withSubjectTableName(WormAuditTables.VERIFICATION).withVisibilityPermission("worm_audit_verification.read"));
      output.add(new QAlertTypeMetaData().withName("wormaudit.export.failed").withLabel("Sealed audit export failed")
         .withSourceQBitName(qBit.getName()).withDefaultSeverity(AlertSeverity.ERROR)
         .withDescription("The audit export could not be sealed with verified retention and object versions.")
         .withSubjectTableName(WormAuditTables.EXPORT).withVisibilityPermission("worm_audit_export.read"));
      for(String job : List.of("verify", "export"))
      {
         String name = "wormaudit." + job + ".daily";
         output.add(new QAlertTypeMetaData().withName(name).withLabel("Daily audit " + job + " overdue")
            .withSourceQBitName(qBit.getName()).withDefaultSeverity(AlertSeverity.ERROR)
            .withDescription("The daily audit " + job + " job has not sent a heartbeat within 26 hours.")
            .withVisibilityPermission(job.equals("verify") ? "worm_audit_verification.read" : "worm_audit_export.read")
            .withDefaultMonitor(AlertDefaultMonitor.heartbeat(name, name, 24 * 3600, 2 * 3600)));
      }
      output.addSelfToInstance(qInstance);
      denyAssistant(qInstance);
      return (new MetaDataProducerMultiOutput());
   }


   /*******************************************************************************
    ** Build schedules from settings available at producer startup.
    *******************************************************************************/
   private void addProcesses(MetaDataProducerMultiOutput output, QBitMetaData qBit)
   {
      for(var process : WormAuditProcesses.processes(qBitConfig))
      {
         process.setSourceQBitName(qBit.getName());
         output.add(process);
      }
      for(var process : ExportProcesses.processes(qBitConfig))
      {
         process.setSourceQBitName(qBit.getName());
         output.add(process);
      }
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
