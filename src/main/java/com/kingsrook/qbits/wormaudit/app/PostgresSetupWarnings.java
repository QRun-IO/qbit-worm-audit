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

package com.kingsrook.qbits.wormaudit.app;


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;


/*******************************************************************************
 ** Read-only PostgreSQL catalog probes; errors become value-free diagnostics.
 *******************************************************************************/
public final class PostgresSetupWarnings
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private PostgresSetupWarnings()
   {
   }


   /*******************************************************************************
    ** Probe the runtime connection, never the configured migration role.
    *******************************************************************************/
   public static List<String> load(QBackendTransaction transaction, WormAuditQBitConfig config)
   {
      List<String> warnings = new ArrayList<>();
      int years = config.effectiveSettings().audit_retention_years();
      if(years != config.getRetentionYears())
      {
         warnings.add("Audit retention setting differs from the configured database purge interval (" + config.getRetentionYears() + " years). A reviewed migration is required.");
      }
      if(!(transaction instanceof RDBMSTransaction rdbms))
      {
         return (warnings);
      }
      try
      {
         var connection = rdbms.getConnection();
         if(!"PostgreSQL".equals(connection.getMetaData().getDatabaseProductName()))
         {
            return (warnings);
         }
         // The live function is authoritative on PostgreSQL, rather than the renderer defaults.
         warnings.clear();
         List<String> tables = new ArrayList<>(config.getCoreAuditTableNames().values());
         tables.addAll(WormAuditTables.ALL.stream().filter(t -> !WormAuditTables.SETTINGS.equals(t)).toList());
         for(String table : tables)
         {
            for(String trigger : List.of("worm_audit_row_guard", "worm_audit_truncate_guard"))
            {
               try(var statement = connection.prepareStatement("SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(?) AND tgname=? AND NOT tgisinternal AND tgenabled IN ('O','A'))"))
               {
                  statement.setString(1, WormAuditDdl.identifier(table));
                  statement.setString(2, trigger);
                  try(var result = statement.executeQuery())
                  {
                     result.next();
                     if(!result.getBoolean(1))
                     {
                        warnings.add("Missing or disabled " + trigger + " on " + table);
                     }
                  }
               }
            }
            try(var statement = connection.prepareStatement("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tableowner=current_user AND to_regclass(quote_ident(schemaname)||'.'||quote_ident(tablename))=to_regclass(?))"))
            {
               statement.setString(1, WormAuditDdl.identifier(table));
               try(var result = statement.executeQuery())
               {
                  result.next();
                  if(result.getBoolean(1))
                  {
                     warnings.add("Runtime role owns audit table " + table);
                  }
               }
            }
         }
         try(var statement = connection.createStatement(); var result = statement.executeQuery("SELECT pg_get_functiondef(to_regprocedure('public.worm_audit_purge(timestamp with time zone)'))"))
         {
            if(result.next() && result.getString(1) != null)
            {
               var interval = java.util.regex.Pattern.compile("(?i)interval\\s+'([0-9]+) years'").matcher(result.getString(1));
               if(interval.find() && Integer.parseInt(interval.group(1)) != years)
               {
                  warnings.add("Audit retention setting differs from the purge function's compiled interval (" + interval.group(1) + " years). A reviewed migration is required.");
               }
            }
         }
         try(var statement = connection.createStatement(); var result = statement.executeQuery("SELECT to_regprocedure('public.worm_audit_purge(timestamp with time zone)') IS NOT NULL"))
         {
            result.next();
            if(!result.getBoolean(1))
            {
               warnings.add("Retention purge function is missing");
            }
         }
      }
      catch(Exception e)
      {
         warnings.add("PostgreSQL setup checks unavailable");
      }
      return (warnings);
   }
}
