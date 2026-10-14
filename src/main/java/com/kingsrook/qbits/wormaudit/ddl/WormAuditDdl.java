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

package com.kingsrook.qbits.wormaudit.ddl;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;


/*******************************************************************************
 ** Render a reviewed migration for the host's physical audit table names.
 ** Core physical columns must use snake_case: audit.id/timestamp,
 ** audit_detail.id/audit_id, audit_table.id/name/label/create_date/modify_date,
 ** and audit_user.id/name/create_date/modify_date. Only table names are rendered;
 ** QInstance field backend-name overrides do not change this DDL contract.
 ** Identifiers are restricted and quoted; configuration is never executable SQL.
 *******************************************************************************/
public final class WormAuditDdl
{
   public static final Map<String, String> DEFAULT_NAMES = Map.of("audit", "audit", "auditDetail", "audit_detail", "auditTable", "audit_table", "auditUser", "audit_user");

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WormAuditDdl()
   {
   }


   /*******************************************************************************
    ** A safe SQL identifier, optionally schema qualified.
    *******************************************************************************/
   public static String identifier(String value)
   {
      if(value == null || !value.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?"))
      {
         throw (new IllegalArgumentException("Invalid SQL identifier"));
      }
      return ("\"" + value.replace(".", "\".\"") + "\"");
   }


   /*******************************************************************************
    ** Resolve backend names while preserving explicit DDL overrides.
    *******************************************************************************/
   public static void resolveNames(WormAuditQBitConfig config, QInstance instance)
   {
      Map<String, String> names = new LinkedHashMap<>();
      for(String name : DEFAULT_NAMES.keySet())
      {
         QTableMetaData table = instance.getTable(name);
         if(table == null)
         {
            throw (new IllegalArgumentException("Core audit table is required: " + name));
         }
         names.put(name, table.getBackendDetails() instanceof RDBMSTableBackendDetails details ? details.getTableName() : DEFAULT_NAMES.get(name));
      }
      names.putAll(config.getCoreAuditTableNames());
      config.withCoreAuditTableNames(Map.copyOf(names));
   }


   /*******************************************************************************
    ** Render the template. Retention is compiled into the function, never a GUC.
    *******************************************************************************/
   public static String postgres(WormAuditQBitConfig config)
   {
      if(config.getRetentionYears() < 1 || config.getAppRole().contains("."))
      {
         throw (new IllegalArgumentException("Invalid retention or app role"));
      }
      try(var stream = WormAuditDdl.class.getResourceAsStream("/com/kingsrook/qbits/wormaudit/ddl/postgres/worm-audit.sql"))
      {
         String sql = new String(java.util.Objects.requireNonNull(stream).readAllBytes(), StandardCharsets.UTF_8);
         Map<String, String> names = new LinkedHashMap<>(DEFAULT_NAMES);
         names.putAll(config.getCoreAuditTableNames());
         for(var entry : DEFAULT_NAMES.entrySet())
         {
            sql = sql.replace("${" + entry.getValue() + "}", identifier(names.get(entry.getKey())));
         }
         return (sql.replace("${app_role}", identifier(config.getAppRole())).replace("${retention}", config.getRetentionYears() + " years"));
      }
      catch(IOException e)
      {
         throw (new IllegalStateException("Cannot read WORM audit DDL", e));
      }
   }
}
