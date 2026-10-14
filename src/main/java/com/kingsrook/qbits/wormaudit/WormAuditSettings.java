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


import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import org.quartz.CronExpression;


/*******************************************************************************
 ** Singleton settings merged over host defaults. Only absent rows/tables fall
 ** back; database outages and invalid persisted settings fail closed.
 *******************************************************************************/
public class WormAuditSettings
{
   private final WormAuditQBitConfig config;
   private final Clock clock;
   private QInstance instance;
   private QRecord cached;
   private Instant expires = Instant.MIN;

   /*******************************************************************************
    ** An immutable snapshot for one run.
    *******************************************************************************/
   public record Values(int audit_retention_years,
      String export_lock_mode,
      int export_retention_days,
      int checkpoint_every_links,
      int checkpoint_every_minutes,
      int chain_interval_seconds,
      int settle_horizon_seconds,
      int late_detail_lookback_hours,
      String export_cron,
      String verify_cron)
   {
   }


   /*******************************************************************************
    ** Use the production clock.
    *******************************************************************************/
   public WormAuditSettings(WormAuditQBitConfig config)
   {
      this(config, Clock.systemUTC());
   }


   /*******************************************************************************
    ** Inject a clock for cache boundary tests.
    *******************************************************************************/
   public WormAuditSettings(WormAuditQBitConfig config, Clock clock)
   {
      this.config = config;
      this.clock = clock;
   }


   /*******************************************************************************
    ** Invalidate after a local edit; other application instances refresh within 30 seconds.
    *******************************************************************************/
   public synchronized void invalidate()
   {
      expires = Instant.MIN;
   }


   /*******************************************************************************
    ** Read at most once per 30 seconds, isolated by QInstance identity.
    *******************************************************************************/
   public synchronized Values read()
   {
      QInstance current = QContext.getQInstance();
      if(current != instance || !clock.instant().isBefore(expires))
      {
         QRecord row = null;
         if(current != null && current.getTable(WormAuditTables.SETTINGS) != null)
         {
            try
            {
               row = new AuditStore(null).get(WormAuditTables.SETTINGS, 1);
            }
            catch(Exception e)
            {
               if(!missingTable(e))
               {
                  throw (new IllegalStateException("Cannot read WORM Audit Settings", e));
               }
            }
         }
         cached = row;
         instance = current;
         expires = row == null ? Instant.MIN : clock.instant().plusSeconds(30);
      }
      QRecord row = defaults(config);
      if(cached != null)
      {
         for(String field : row.getValues().keySet())
         {
            if(cached.getValue(field) != null)
            {
               row.setValue(field, cached.getValue(field));
            }
         }
      }
      validate(row);
      return (new Values(row.getValueInteger("audit_retention_years"),
         row.getValueString("export_lock_mode"),
         row.getValueInteger("export_retention_days"),
         row.getValueInteger("checkpoint_every_links"),
         row.getValueInteger("checkpoint_every_minutes"),
         row.getValueInteger("chain_interval_seconds"),
         row.getValueInteger("settle_horizon_seconds"),
         row.getValueInteger("late_detail_lookback_hours"),
         row.getValueString("export_cron"),
         row.getValueString("verify_cron")));
   }


   /*******************************************************************************
    ** Build insert-only seed values from the host defaults.
    *******************************************************************************/
   public static QRecord defaults(WormAuditQBitConfig config)
   {
      return (new QRecord().withValue("id", 1)
         .withValue("audit_retention_years", config.getRetentionYears())
         .withValue("export_lock_mode", config.getExportLockMode())
         .withValue("export_retention_days", config.getExportRetentionDays())
         .withValue("checkpoint_every_links", config.getCheckpointEveryLinks())
         .withValue("checkpoint_every_minutes", config.getCheckpointEveryMinutes())
         .withValue("chain_interval_seconds", config.getChainIntervalSeconds())
         .withValue("settle_horizon_seconds", config.getSettleHorizonSeconds())
         .withValue("late_detail_lookback_hours", config.getLateDetailLookbackHours())
         .withValue("export_cron", config.getExportCron())
         .withValue("verify_cron", config.getVerifyCron()));
   }


   /*******************************************************************************
    ** Validate supplied fields; partial updates leave omitted fields untouched.
    *******************************************************************************/
   public static void validate(QRecord row)
   {
      if(row.getValue("id") != null && !Integer.valueOf(1).equals(row.getValueInteger("id")))
      {
         throw (new IllegalArgumentException("WORM Audit Settings has one row only (ID 1)."));
      }
      range(row, "audit_retention_years", "Audit retention years", 1, 100);
      range(row, "export_retention_days", "Export retention days", 1, 36500);
      range(row, "checkpoint_every_links", "Checkpoint every links", 1, 2147483647);
      range(row, "checkpoint_every_minutes", "Checkpoint every minutes", 1, 2147483647);
      range(row, "chain_interval_seconds", "Chain interval seconds", 1, 2147483647);
      range(row, "settle_horizon_seconds", "Settle horizon seconds", 0, 2147483647);
      range(row, "late_detail_lookback_hours", "Late detail lookback hours", 1, 2147483647);
      if(row.getValues().containsKey("export_lock_mode") && !java.util.Arrays.asList("GOVERNANCE", "COMPLIANCE").contains(row.getValueString("export_lock_mode")))
      {
         throw (new IllegalArgumentException("Export lock mode must be GOVERNANCE or COMPLIANCE."));
      }
      for(String field : java.util.List.of("export_cron", "verify_cron"))
      {
         if(row.getValues().containsKey(field) && (row.getValueString(field) == null || !CronExpression.isValidExpression(row.getValueString(field))))
         {
            throw (new IllegalArgumentException((field.equals("export_cron") ? "Export" : "Verify") + " schedule must be a valid Quartz cron expression (UTC)."));
         }
      }
   }


   /*******************************************************************************
    ** Reject null, fractional and out-of-range numbers with a plain field label.
    *******************************************************************************/
   private static void range(QRecord row, String field, String label, int minimum, int maximum)
   {
      if(!row.getValues().containsKey(field))
      {
         return;
      }
      try
      {
         long value = Long.parseLong(String.valueOf(row.getValue(field)));
         if(value >= minimum && value <= maximum)
         {
            return;
         }
      }
      catch(NumberFormatException ignored)
      {
         // Use the same clear message for invalid numbers and invalid ranges.
      }
      throw (new IllegalArgumentException(label + " must be a whole number from " + minimum + " to " + maximum + "."));
   }


   /*******************************************************************************
    ** Recognize PostgreSQL/H2 missing-table errors without hiding other failures.
    *******************************************************************************/
   private static boolean missingTable(Throwable error)
   {
      for(Throwable cause = error; cause != null; cause = cause.getCause())
      {
         if(cause instanceof SQLException sql && ("42P01".equals(sql.getSQLState()) || "42S02".equals(sql.getSQLState()) || "42S04".equals(sql.getSQLState())))
         {
            return (true);
         }
      }
      return (false);
   }
}
