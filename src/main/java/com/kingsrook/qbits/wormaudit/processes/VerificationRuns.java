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


import java.time.Instant;
import java.util.List;
import java.util.Set;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.VerificationResult;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.alerts.AlertRecordRef;
import com.kingsrook.qqq.backend.core.alerts.AlertSignal;
import com.kingsrook.qqq.backend.core.alerts.QAlerts;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Verification run persistence and the core alerts SPI. Both UI and schedule
 ** write exactly one immutable result row; only schedules change alert state.
 *******************************************************************************/
public final class VerificationRuns
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private VerificationRuns()
   {
   }


   /*******************************************************************************
    ** Resolve this instance's configuration, never a global cross-instance cache.
    *******************************************************************************/
   public static WormAuditQBitConfig config()
   {
      return (QContext.getQInstance().getQBits().values().stream().map(q -> q.getConfig()).filter(WormAuditQBitConfig.class::isInstance)
         .map(WormAuditQBitConfig.class::cast).findFirst().orElseThrow(() -> new IllegalStateException("WORM audit qbit is not installed")));
   }


   /*******************************************************************************
    ** Verify and persist, sending a heartbeat even if a scheduled run errors.
    *******************************************************************************/
   public static VerificationResult run(Set<Long> selection, String trigger) throws QException
   {
      boolean scheduled = "SCHEDULE".equals(trigger);
      try
      {
         VerificationResult result = new WormAuditVerifier(config()).verify(selection);
         QRecord row = save(result, trigger);
         if(scheduled)
         {
            if(result.passed())
            {
               QAlerts.resolve("worm_audit.chain.break", "chain", "Audit chain verification passed");
            }
            else
            {
               QAlerts.raise(new AlertSignal("worm_audit.chain.break").withDedupKey("chain")
                  .withTitle(result.getBreaks().getFirst().reason()).withRecordRef(new AlertRecordRef(WormAuditTables.VERIFICATION, row.getValue("id"))));
            }
         }
         return (result);
      }
      finally
      {
         if(scheduled)
         {
            QAlerts.heartbeat("worm_audit.verify.daily");
         }
      }
   }


   /*******************************************************************************
    ** Persist identifiers and a value-free first reason, never audit content.
    *******************************************************************************/
   public static QRecord save(VerificationResult result, String trigger) throws QException
   {
      return (save(result, trigger, null));
   }


   /*******************************************************************************
    ** Append a chain or sealed-export result using the same immutable schema.
    *******************************************************************************/
   public static QRecord save(VerificationResult result, String trigger, Long exportId) throws QException
   {
      String user = QContext.getQSession() == null || QContext.getQSession().getUser() == null ? "system" : QContext.getQSession().getUser().getIdReference();
      QRecord row = new QRecord().withValue("kind", exportId == null ? "CHAIN" : "SEALED_EXPORT").withValue("export_id", exportId).withValue("trigger", trigger)
         .withValue("started_at", result.getStartedAt()).withValue("finished_at", Instant.now())
         .withValue("from_link_id", result.getFromLinkId()).withValue("to_link_id", result.getToLinkId())
         .withValue("links_checked", result.getLinksChecked()).withValue("outcome", result.passed() ? "PASS" : "FAIL")
         .withValue("break_count", result.getBreakCount()).withValue("run_by", user);
      if(!result.passed())
      {
         var first = result.getBreaks().getFirst();
         row.withValue("first_break_link_id", first.linkId()).withValue("first_break_audit_id", first.auditId()).withValue("first_break_reason", first.reason());
      }
      return (new AuditStore(null).insert(WormAuditTables.VERIFICATION, List.of(row)).getFirst());
   }
}
