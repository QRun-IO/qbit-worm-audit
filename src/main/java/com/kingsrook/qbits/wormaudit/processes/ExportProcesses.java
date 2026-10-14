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

package com.kingsrook.qbits.wormaudit.processes;


import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.export.SealedExportVerifier;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.export.SealedStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.permissions.UseOtherPermissionNameCustomPermissionChecker;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLineInterface;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractExtractStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractLoadStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractTransformStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunInput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunOutput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ExtractViaQueryStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ProcessSummaryProviderInterface;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;


/*******************************************************************************
 ** Standard Review/Result actions for sealing and verifying exports.
 *******************************************************************************/
public final class ExportProcesses
{
   public static final String EXPORT = "worm_audit_export_now";
   public static final String VERIFY = "worm_audit_verify_export";
   public static final String DAILY = "worm_audit_export_daily";
   public static final String PERMISSION = "worm_audit.export";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private ExportProcesses()
   {
   }


   /*******************************************************************************
    ** Export is a table action; verification requires one or more selected exports.
    *******************************************************************************/
   public static List<QProcessMetaData> processes(WormAuditQBitConfig config)
   {
      var settings = config.effectiveSettings();
      Map<String, Serializable> values = new HashMap<>();
      values.put(StreamedETLWithFrontendProcess.FIELD_SOURCE_TABLE, WormAuditTables.EXPORT);
      values.put(StreamedETLWithFrontendProcess.FIELD_DESTINATION_TABLE, WormAuditTables.EXPORT);
      values.put(StreamedETLWithFrontendProcess.FIELD_SUPPORTS_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_DO_FULL_VALIDATION, true);
      QProcessMetaData export = StreamedETLWithFrontendProcess.defineProcessMetaData(ExportExtract.class, ExportReview.class, ExportLoad.class, new HashMap<>(values))
         .withName(EXPORT).withLabel("Export now").withTableName(WormAuditTables.EXPORT).withPermissionRules(permission(PERMISSION));
      QProcessMetaData verify = StreamedETLWithFrontendProcess.defineProcessMetaData(VerifyExtract.class, VerifyReview.class, VerifyLoad.class, new HashMap<>(values))
         .withName(VERIFY).withLabel("Verify sealed export").withTableName(WormAuditTables.EXPORT).withMinInputRecords(1)
         .withPermissionRules(permission(WormAuditProcesses.PERMISSION));
      QProcessMetaData daily = new QProcessMetaData().withName(DAILY).withLabel("Daily sealed audit export")
         .withStep(new QBackendStepMetaData().withName("export").withCode(new QCodeReference(Daily.class)))
         .withPermissionRules(permission(PERMISSION)).withSchedule(new QScheduleMetaData().withSchedulerName(config.getSchedulerName())
            .withCronExpression(settings.export_cron()).withCronTimeZoneId("UTC"));
      return (List.of(export, verify, daily));
   }


   /*******************************************************************************
    ** Reuse the phase (a) explicit permission-name checker.
    *******************************************************************************/
   private static QPermissionRules permission(String name)
   {
      return (new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)
         .withCustomPermissionChecker(UseOtherPermissionNameCustomPermissionChecker.build(name)));
   }


   /*******************************************************************************
    ** Plain text summaries must not acquire the framework's default zero count.
    *******************************************************************************/
   private static ProcessSummaryLine text(Status status, String message)
   {
      ProcessSummaryLine line = new ProcessSummaryLine(status, message);
      line.setCount(null);
      return (line);
   }


   /*******************************************************************************
    ** One synthetic work item allows the first export on an empty export table.
    *******************************************************************************/
   public static class ExportExtract extends AbstractExtractStep
   {
      /*******************************************************************************
       ** Count the single export operation, not previous export rows.
       *******************************************************************************/
      @Override
      public Integer doCount(RunBackendStepInput input)
      {
         return (1);
      }


      /*******************************************************************************
       ** Feed one work item through the standard stream.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         getRecordPipe().addRecord(new QRecord().withValue("id", 0L));
      }
   }


   /*******************************************************************************
    ** Review is read-only; the writer reselects the suffix after confirmation.
    *******************************************************************************/
   public static class ExportReview extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private String message;
      private boolean failed;

      /*******************************************************************************
       ** Read the planned range once without uploading or inserting.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         try
         {
            message = SealedExporter.scope(new AuditStore(null)).review();
            failed = false;
         }
         catch(QException e)
         {
            message = "Cannot select a contiguous export range";
            failed = true;
         }
         output.getRecords().addAll(input.getRecords());
      }


      /*******************************************************************************
       ** Show the range, including the explicit no-checkpoint case.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         return (new ArrayList<>(List.of(text(failed ? Status.ERROR : Status.INFO, message == null ? "Nothing to seal: no new checkpoint" : message))));
      }
   }


   /*******************************************************************************
    ** Seal once after the stream is complete.
    *******************************************************************************/
   public static class ExportLoad extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private final SealedStore storage;
      private SealedExporter.Result result;

      /*******************************************************************************
       ** Framework constructor.
       *******************************************************************************/
      public ExportLoad()
      {
         this(null);
      }

      /*******************************************************************************
       ** Storage-injected action for unit tests.
       *******************************************************************************/
      public ExportLoad(SealedStore storage)
      {
         this.storage = storage;
      }


      /*******************************************************************************
       ** Forward the work item without retaining content.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output)
      {
         output.getRecords().addAll(input.getRecords());
      }


      /*******************************************************************************
       ** The same execution path as the daily schedule.
       *******************************************************************************/
      @Override
      public void postRun(BackendStepPostRunInput input, BackendStepPostRunOutput output)
      {
         result = new SealedExporter(VerificationRuns.config(), storage).run("USER", Instant.now());
      }


      /*******************************************************************************
       ** Result text is value-free even when the provider fails.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         return (result == null ? new ArrayList<>() : new ArrayList<>(List.of(text(result.failed() ? Status.ERROR : Status.OK, result.message()))));
      }
   }


   /*******************************************************************************
    ** Respect core's selected-record/filter interpretation; no implicit all-export run.
    *******************************************************************************/
   public static class VerifyExtract extends ExtractViaQueryStep
   {
      /*******************************************************************************
       ** Deterministic selection with full text fields from the export table.
       *******************************************************************************/
      @Override
      public QQueryFilter getQueryFilter(RunBackendStepInput input) throws QException
      {
         input.addValue(FIELD_SOURCE_TABLE, WormAuditTables.EXPORT);
         QQueryFilter filter = super.getQueryFilter(input).clone();
         filter.setOrderBys(List.of(new QFilterOrderBy("id", true)));
         return (filter);
      }
   }


   /*******************************************************************************
    ** Review selected exports without reading their content.
    *******************************************************************************/
   public static class VerifyReview extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private long count;

      /*******************************************************************************
       ** Count and forward the selected export records.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output)
      {
         count += input.getRecords().size();
         output.getRecords().addAll(input.getRecords());
      }


      /*******************************************************************************
       ** One Review summary.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         return (new ArrayList<>(List.of(text(Status.INFO, WormAuditVerifier.number(count) + " sealed exports will be verified"))));
      }
   }


   /*******************************************************************************
    ** Verify each selected export and persist its independent result.
    *******************************************************************************/
   public static class VerifyLoad extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private final SealedStore storage;
      private final ArrayList<ProcessSummaryLineInterface> lines = new ArrayList<>();

      /*******************************************************************************
       ** Framework constructor.
       *******************************************************************************/
      public VerifyLoad()
      {
         this(null);
      }

      /*******************************************************************************
       ** Storage-injected action for unit tests.
       *******************************************************************************/
      public VerifyLoad(SealedStore storage)
      {
         this.storage = storage;
      }


      /*******************************************************************************
       ** Process the current page without retaining exported content.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         for(QRecord selected : input.getRecords())
         {
            QRecord row = new AuditStore(null).get(WormAuditTables.EXPORT, selected.getValueLong("id"));
            if(row == null)
            {
               lines.add(text(Status.ERROR, "Selected export " + selected.getValueLong("id") + " is missing"));
               continue;
            }
            var report = new SealedExportVerifier(VerificationRuns.config(), storage).verify(row, "USER");
            if(report.result().passed())
            {
               lines.add(text(Status.OK, WormAuditVerifier.number(report.result().getLinksChecked()) + " links verified in export " + row.getValueLong("id")));
            }
            report.result().getBreaks().forEach(b -> lines.add(text(Status.ERROR, b.reason())));
            if(report.purged() > 0 && report.result().passed())
            {
               lines.add(text(Status.INFO, WormAuditVerifier.number(report.purged()) + " links verified from the sealed copy only (purged from the live database)"));
            }
         }
      }


      /*******************************************************************************
       ** Exact per-link differences and purged-copy information.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         return (lines);
      }
   }


   /*******************************************************************************
    ** Daily export sends heartbeat even when sealing fails.
    *******************************************************************************/
   public static class Daily implements BackendStep
   {
      /*******************************************************************************
       ** Run the exporter with the installed host configuration.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output)
      {
         var result = new SealedExporter(VerificationRuns.config()).run("SCHEDULE", Instant.now());
         output.addValue("outcome", result.failed() ? "FAIL" : "PASS");
         output.addValue("result", result.message());
      }
   }
}

