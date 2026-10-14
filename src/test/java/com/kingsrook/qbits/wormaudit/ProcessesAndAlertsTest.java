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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qbits.wormaudit.processes.WormAuditProcesses;
import com.kingsrook.qqq.backend.core.alerts.AlertResolution;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.AlertSinkInterface;
import com.kingsrook.qqq.backend.core.alerts.AlertsInstanceMetaData;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunInput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunOutput;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.core;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.tamper;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Tests and fixtures for processes and alerts test.
 *******************************************************************************/
class ProcessesAndAlertsTest
{
   /*******************************************************************************
    ** Tests and fixtures for sink.
    *******************************************************************************/
   public static class Sink implements AlertSinkInterface
   {
      static final List<AlertSignal> raised = new ArrayList<>();
      static final List<AlertResolution> resolved = new ArrayList<>();
      static final List<String> beats = new ArrayList<>();

      /*******************************************************************************
       ** Verify raise.
       *******************************************************************************/
      public void raise(AlertSignal signal)
      {
         raised.add(signal);
      }

      /*******************************************************************************
       ** Verify resolve.
       *******************************************************************************/
      public void resolve(AlertResolution resolution)
      {
         resolved.add(resolution);
      }

      /*******************************************************************************
       ** Verify heartbeat.
       *******************************************************************************/
      public void heartbeat(String key, Instant at)
      {
         beats.add(key);
      }
   }

   /*******************************************************************************
    ** RC.5 validates declared severities, names and daily heartbeat expectations.
    *******************************************************************************/
   @Test
   void alertTypesAndDailyMonitors() throws Exception
   {
      var instance = init(new WormAuditQBitConfig());
      new com.kingsrook.qqq.backend.core.instances.QInstanceValidator().validate(instance);
      assertThat(new com.kingsrook.qbits.wormaudit.chain.AuditStore(null).isMemory()).isTrue();
      var types = AlertsInstanceMetaData.of(instance).getAlertTypes();
      assertThat(types).containsOnlyKeys("wormaudit.chain.break", "wormaudit.export.failed", "wormaudit.verify.daily", "wormaudit.export.daily");
      assertThat(types.get("wormaudit.chain.break").getDefaultSeverity())
         .isEqualTo(com.kingsrook.qqq.backend.core.alerts.AlertSeverity.CRITICAL);
      assertThat(types.get("wormaudit.export.failed").getDefaultSeverity())
         .isEqualTo(com.kingsrook.qqq.backend.core.alerts.AlertSeverity.ERROR);
      types.values().forEach(type ->
      {
         assertThat(type.getLabel()).isNotBlank();
         assertThat(type.getDescription()).isNotBlank();
         assertThat(AlertsInstanceMetaData.ALERT_TYPE_NAME_PATTERN.matcher(type.getName()).matches()).isTrue();
      });
      for(String name : List.of("wormaudit.verify.daily", "wormaudit.export.daily"))
      {
         var monitors = types.get(name).getDefaultMonitors();
         assertThat(monitors).hasSize(1);
         assertThat(monitors.getFirst().getKind()).isEqualTo(com.kingsrook.qqq.backend.core.alerts.AlertMonitorKind.HEARTBEAT);
         assertThat(monitors.getFirst().getDefinition()).containsEntry("heartbeatKey", name)
            .containsEntry("expectedEverySeconds", 86400).containsEntry("graceSeconds", 7200);
      }
   }


   /*******************************************************************************
    ** Verify daily raise resolve heartbeat and user result.
    *******************************************************************************/
   @Test
   void dailyRaiseResolveHeartbeatAndUserResult() throws Exception
   {
      var config = ChainVerificationTest.signed();
      var instance = init(config);
      Sink.raised.clear();
      Sink.resolved.clear();
      Sink.beats.clear();
      AlertsInstanceMetaData.ofOrWithNew(instance).withSink(new QCodeReference(Sink.class));
      audit(1);
      detail(1, 1);
      new WormAuditProcesses.ChainTick()
            .run(new RunBackendStepInput(), new RunBackendStepOutput());
      tamper("auditDetail", 1, "newValue", "broken");
      var daily = new WormAuditProcesses.Daily();
      var output = new RunBackendStepOutput();
      daily.run(new RunBackendStepInput(), output);
      assertThat(output.getValueString("outcome")).isEqualTo("FAIL");
      assertThat(Sink.raised).hasSize(1);
      assertThat(Sink.raised.getFirst().getAlertTypeName()).isEqualTo("wormaudit.chain.break");
      assertThat(Sink.raised.getFirst().getDedupKey()).isEqualTo("chain");
      assertThat(Sink.raised.getFirst().getRecordRefs().getFirst().getTableName())
            .isEqualTo(WormAuditTables.VERIFICATION);
      assertThat(Sink.raised.getFirst().getTitle()).contains("Break at link 1");
      var first = STORE.all(WormAuditTables.VERIFICATION).getFirst();
      assertThat(first.getValueLong("first_break_link_id")).isEqualTo(1);
      assertThat(first.getValueLong("first_break_audit_id")).isEqualTo(1);
      assertThat(first.getValueString("trigger")).isEqualTo("SCHEDULE");
      tamper("auditDetail", 1, "newValue", "new");
      daily.run(new RunBackendStepInput(), new RunBackendStepOutput());
      assertThat(Sink.resolved).hasSize(1);
      assertThat(Sink.beats)
            .containsExactly("wormaudit.verify.daily", "wormaudit.verify.daily");
      assertThat(STORE.all(WormAuditTables.VERIFICATION)).hasSize(2);
      assertThat(VerificationRuns.run(null, "USER").passed()).isTrue();
      assertThat(Sink.beats).hasSize(2);
   }

   /*******************************************************************************
    ** Verify review and load across pages including failures and empty scope.
    *******************************************************************************/
   @Test
   void reviewAndLoadAcrossPagesIncludingFailuresAndEmptyScope() throws Exception
   {
      var config = new WormAuditQBitConfig();
      init(config);
      audit(1);
      audit(2);
      new WormAuditChainer(config).chainOnce();
      var links = STORE.all(WormAuditTables.CHAIN);
      var review = new WormAuditProcesses.Review();
      var load = new WormAuditProcesses.Load();
      var output = new RunBackendStepOutput();
      assertThat(load.getProcessSummary(output, true)).isEmpty();
      for(var link : links)
      {
         var input = new RunBackendStepInput().withRecords(List.of(link));
         review.runOnePage(input, output);
         load.runOnePage(input, output);
      }
      assertThat(review.getProcessSummary(output, false).toString())
            .contains("2 chain links will be verified", "0 checkpoints");
      load.postRun(
            new BackendStepPostRunInput(new RunBackendStepInput()),
            new BackendStepPostRunOutput(output));
      assertThat(STORE.all(WormAuditTables.VERIFICATION)).hasSize(1);
      assertThat(load.getProcessSummary(output, true).toString())
            .contains("2 links verified", "no signing key configured");
      audit(3);
      var fullWithEmptyFilter = new WormAuditProcesses.Load();
      fullWithEmptyFilter.runOnePage(new RunBackendStepInput().withRecords(links), output);
      fullWithEmptyFilter.postRun(new BackendStepPostRunInput(new RunBackendStepInput().addValue("queryFilterJson", "{}")),
         new BackendStepPostRunOutput(output));
      assertThat(fullWithEmptyFilter.getProcessSummary(output, true).toString()).contains("audit 3 is not covered by the chain");
      tamper("audit", 1, "message", "changed");
      var selected = new WormAuditProcesses.Load();
      selected.runOnePage(
            new RunBackendStepInput().withRecords(List.of(links.getFirst())), output);
      selected.postRun(
            new BackendStepPostRunInput(new RunBackendStepInput().addValue("recordIds", "1")),
            new BackendStepPostRunOutput(output));
      assertThat(selected.getProcessSummary(output, true).toString())
            .contains("ERROR", "content differs");
      init(config);
      var empty = new WormAuditProcesses.Load();
      empty.postRun(
            new BackendStepPostRunInput(new RunBackendStepInput()),
            new BackendStepPostRunOutput(output));
      assertThat(empty.getProcessSummary(output, true).toString()).contains("0 links verified");
      assertThat(new WormAuditProcesses.Review().getProcessSummary(output, false).toString())
            .contains("links none");
   }

   /*******************************************************************************
    ** Full loads retain no id collection; review summarizes disjoint streamed pages once.
    *******************************************************************************/
   @Test
   void reviewRangesAndSelectionOnlyIds() throws Exception
   {
      var config = ChainVerificationTest.signed().withCheckpointEveryLinks(2);
      init(config);
      for(long id = 1; id <= 4; id++)
      {
         audit(id);
      }
      new WormAuditChainer(config).chainOnce();
      var links = STORE.all(WormAuditTables.CHAIN);
      var review = new WormAuditProcesses.Review();
      var full = new WormAuditProcesses.Load();
      var selected = new WormAuditProcesses.Load();
      var output = new RunBackendStepOutput();
      var ids = WormAuditProcesses.Load.class.getDeclaredField("ids");
      ids.setAccessible(true);
      for(var link : links)
      {
         var input = new RunBackendStepInput().withRecords(List.of(link));
         review.runOnePage(input, output);
         full.runOnePage(input, output);
         assertThat(ids.get(full)).isNull();
      }
      String summary = review.getProcessSummary(output, false).toString();
      assertThat(summary).contains("4 chain links", "links 1–4", "2 checkpoints");
      // A second call reuses the count; later inserts cannot silently change Review.
      STORE.insert(WormAuditTables.CHECKPOINT, List.of(new com.kingsrook.qqq.backend.core.model.data.QRecord()
         .withValue("from_link_id", 1L).withValue("to_link_id", 4L)));
      assertThat(review.getProcessSummary(output, false).toString()).isEqualTo(summary);
      selected.runOnePage(new RunBackendStepInput().addValue("recordIds", "2").withRecords(List.of(links.get(1))), output);
      assertThat(ids.get(selected)).isEqualTo(java.util.Set.of(2L));
   }


   /*******************************************************************************
    ** Docker dependencies must not enable debug wire logs during tests.
    *******************************************************************************/
   @Test
   void dockerLoggersAreQuiet()
   {
      for(String name : List.of("org.testcontainers", "com.github.dockerjava", "org.apache.hc", "tc"))
      {
         assertThat(org.apache.logging.log4j.LogManager.getLogger(name).isDebugEnabled()).isFalse();
         assertThat(org.apache.logging.log4j.LogManager.getLogger(name).isWarnEnabled()).isTrue();
      }
   }

}
