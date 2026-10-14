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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.VerificationResult;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.permissions.UseOtherPermissionNameCustomPermissionChecker;
import com.kingsrook.qqq.backend.core.actions.processes.BackendStep;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLine;
import com.kingsrook.qqq.backend.core.model.actions.processes.ProcessSummaryLineInterface;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepInput;
import com.kingsrook.qqq.backend.core.model.actions.processes.RunBackendStepOutput;
import com.kingsrook.qqq.backend.core.model.actions.processes.Status;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QBackendStepMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.processes.QProcessMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.scheduleing.QScheduleMetaData;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractLoadStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.AbstractTransformStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunInput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.BackendStepPostRunOutput;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.CouldNotFindQueryFilterForExtractStepException;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ExtractViaQueryStep;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.ProcessSummaryProviderInterface;
import com.kingsrook.qqq.backend.core.processes.implementations.etl.streamedwithfrontend.StreamedETLWithFrontendProcess;


/*******************************************************************************
 ** Standard streamed ETL Review/Result action plus two scheduled-only processes.
 ** No process is an app navigation entry.
 *******************************************************************************/
public final class WormAuditProcesses
{
   public static final String VERIFY = "worm_audit_verify_chain";
   public static final String CHAIN = "worm_audit_chain_tick";
   public static final String DAILY = "worm_audit_verify_daily";
   public static final String PERMISSION = "worm_audit.verify";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WormAuditProcesses()
   {
   }


   /*******************************************************************************
    ** Metadata for table/record verification and scheduled background work.
    *******************************************************************************/
   public static List<QProcessMetaData> processes(WormAuditQBitConfig config)
   {
      Map<String, Serializable> values = new HashMap<>();
      values.put(StreamedETLWithFrontendProcess.FIELD_SOURCE_TABLE, WormAuditTables.CHAIN);
      values.put(StreamedETLWithFrontendProcess.FIELD_DESTINATION_TABLE, WormAuditTables.CHAIN);
      values.put(StreamedETLWithFrontendProcess.FIELD_SUPPORTS_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_DO_FULL_VALIDATION, true);
      values.put(StreamedETLWithFrontendProcess.FIELD_PREVIEW_MESSAGE, "Verify live audit content, link continuity and signed checkpoints.");
      QProcessMetaData verify = StreamedETLWithFrontendProcess.defineProcessMetaData(Extract.class, Review.class, Load.class, values)
         .withName(VERIFY).withLabel("Verify audit chain").withTableName(WormAuditTables.CHAIN).withPermissionRules(permission());
      QProcessMetaData chain = new QProcessMetaData().withName(CHAIN).withLabel("Chain settled audit records")
         .withStep(new QBackendStepMetaData().withName("chain").withCode(new QCodeReference(ChainTick.class)))
         .withPermissionRules(permission()).withSchedule(new QScheduleMetaData().withSchedulerName(config.getSchedulerName())
            .withRepeatSeconds(config.getChainIntervalSeconds()).withInitialDelaySeconds(config.getChainIntervalSeconds()));
      QProcessMetaData daily = new QProcessMetaData().withName(DAILY).withLabel("Daily audit chain verification")
         .withStep(new QBackendStepMetaData().withName("verify").withCode(new QCodeReference(Daily.class)))
         .withPermissionRules(permission()).withSchedule(new QScheduleMetaData().withSchedulerName(config.getSchedulerName())
            .withCronExpression(config.getVerifyCron()).withCronTimeZoneId("UTC"));
      return (List.of(verify, chain, daily));
   }


   /*******************************************************************************
    ** One explicit permission, not process-name access suffixes.
    *******************************************************************************/
   private static QPermissionRules permission()
   {
      return (new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)
         .withCustomPermissionChecker(UseOtherPermissionNameCustomPermissionChecker.build(PERMISSION)));
   }


   /*******************************************************************************
    ** Use core selection/filter interpretation, with a full-chain default. An
    ** empty frontend filter means a full run, so completeness is still checked.
    *******************************************************************************/
   public static class Extract extends ExtractViaQueryStep
   {
      /*******************************************************************************
       ** Extract links in id order and make the effective scope available to Load.
       *******************************************************************************/
      @Override
      public QQueryFilter getQueryFilter(RunBackendStepInput input) throws QException
      {
         input.addValue(FIELD_SOURCE_TABLE, WormAuditTables.CHAIN);
         QQueryFilter filter;
         try
         {
            filter = super.getQueryFilter(input).clone();
         }
         catch(CouldNotFindQueryFilterForExtractStepException expected)
         {
            filter = new QQueryFilter();
         }
         filter.setOrderBys(List.of(new QFilterOrderBy("id", true)));
         return (filter);
      }
   }


   /*******************************************************************************
    ** Review counts the streamed selection without verifying or writing rows.
    *******************************************************************************/
   public static class Review extends AbstractTransformStep implements ProcessSummaryProviderInterface
   {
      private long count;
      private long min = Long.MAX_VALUE;
      private long max = Long.MIN_VALUE;
      private Long checkpoints;

      /*******************************************************************************
       ** Accumulate the scope and forward links to the loader.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         for(QRecord record : input.getRecords())
         {
            count++;
            min = Math.min(min, record.getValueLong("id"));
            max = Math.max(max, record.getValueLong("id"));
         }
         checkpoints = null;
         output.getRecords().addAll(input.getRecords());
      }


      /*******************************************************************************
       ** Standard Review line, including the link range and checkpoint count.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         if(checkpoints == null)
         {
            try
            {
               CountInput input = new CountInput(WormAuditTables.CHECKPOINT).withFilter(new QQueryFilter(
                  new QFilterCriteria("from_link_id", QCriteriaOperator.LESS_THAN_OR_EQUALS, max),
                  new QFilterCriteria("to_link_id", QCriteriaOperator.GREATER_THAN_OR_EQUALS, min)));
               input.withPermissionBypass("WORM audit internal review");
               checkpoints = count == 0 ? 0L : new CountAction().execute(input).getCount().longValue();
            }
            catch(QException e)
            {
               return (new ArrayList<>(List.of(new ProcessSummaryLine(Status.ERROR, "Cannot count overlapping audit checkpoints"))));
            }
         }
         String range = count == 0 ? "none" : WormAuditVerifier.number(min) + "–" + WormAuditVerifier.number(max);
         return (new ArrayList<>(List.of(new ProcessSummaryLine(Status.INFO, WormAuditVerifier.number(count)
            + " chain links will be verified (links " + range + ", " + WormAuditVerifier.number(checkpoints) + " checkpoints)"))));
      }
   }


   /*******************************************************************************
    ** Load collects selected ids, then performs one snapshot verification in
    ** postRun and appends one result row, including for an empty chain.
    *******************************************************************************/
   public static class Load extends AbstractLoadStep implements ProcessSummaryProviderInterface
   {
      private Set<Long> ids;
      private VerificationResult result;

      /*******************************************************************************
       ** Retain ids only, not audit content, across streamed pages.
       *******************************************************************************/
      @Override
      public void runOnePage(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         if(selected(new Extract().getQueryFilter(input)))
         {
            if(ids == null)
            {
               ids = new HashSet<>();
            }
            input.getRecords().forEach(r -> ids.add(r.getValueLong("id")));
         }
         output.getRecords().addAll(input.getRecords());
      }


      /*******************************************************************************
       ** Run once after all pages. Explicit filters are selection runs.
       *******************************************************************************/
      @Override
      public void postRun(BackendStepPostRunInput input, BackendStepPostRunOutput output) throws QException
      {
         QQueryFilter filter = new Extract().getQueryFilter(input);
         if(selected(filter) && ids == null)
         {
            // Some callers supply the effective selection only to postRun.
            ids = new HashSet<>();
            new AuditStore(null).query(WormAuditTables.CHAIN, filter).forEach(r -> ids.add(r.getValueLong("id")));
         }
         result = VerificationRuns.run(selected(filter) ? ids : null, "USER");
      }


      /*******************************************************************************
       ** Empty filters preserve full completeness verification and retain no ids.
       *******************************************************************************/
      private boolean selected(QQueryFilter filter)
      {
         return ((filter.getCriteria() != null && !filter.getCriteria().isEmpty())
            || (filter.getSubFilters() != null && !filter.getSubFilters().isEmpty())
            || filter.getLimit() != null || (filter.getSkip() != null && filter.getSkip() > 0));
      }


      /*******************************************************************************
       ** One ERROR per exact break; warnings remain visible on a passing run.
       *******************************************************************************/
      @Override
      public ArrayList<ProcessSummaryLineInterface> getProcessSummary(RunBackendStepOutput output, boolean isForResultScreen)
      {
         ArrayList<ProcessSummaryLineInterface> lines = new ArrayList<>();
         if(result == null)
         {
            return (lines);
         }
         if(result.passed())
         {
            lines.add(new ProcessSummaryLine(Status.OK, WormAuditVerifier.number(result.getLinksChecked()) + " links verified"));
         }
         result.getBreaks().forEach(b -> lines.add(new ProcessSummaryLine(Status.ERROR, b.reason())));
         result.getWarnings().forEach(w -> lines.add(new ProcessSummaryLine(Status.WARNING, w)));
         return (lines);
      }
   }


   /*******************************************************************************
    ** Scheduled writer tick.
    *******************************************************************************/
   public static class ChainTick implements BackendStep
   {
      /*******************************************************************************
       ** Append settled work under the shared writer lock.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         output.addValue("linksChained", new WormAuditChainer(VerificationRuns.config()).chainOnce().links());
      }
   }


   /*******************************************************************************
    ** Daily verification, including alerts and heartbeat.
    *******************************************************************************/
   public static class Daily implements BackendStep
   {
      /*******************************************************************************
       ** Verify the full settled chain.
       *******************************************************************************/
      @Override
      public void run(RunBackendStepInput input, RunBackendStepOutput output) throws QException
      {
         output.addValue("outcome", VerificationRuns.run(null, "SCHEDULE").passed() ? "PASS" : "FAIL");
      }
   }
}
