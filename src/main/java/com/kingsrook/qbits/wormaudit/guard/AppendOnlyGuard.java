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

package com.kingsrook.qbits.wormaudit.guard;


import java.sql.SQLException;
import java.util.List;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Metadata defense and a value-free mapping of the database write-once error.
 *******************************************************************************/
public class AppendOnlyGuard implements MetaDataCustomizerInterface<QTableMetaData>
{
   public static final List<String> CORE_TABLES = List.of("audit", "auditDetail", "auditTable", "auditUser");
   public static final String MESSAGE = "Audit records are write-once and cannot be changed or deleted.";

   /*******************************************************************************
    ** Protect core and sidecar audit metadata after host customization.
    *******************************************************************************/
   @Override
   public QTableMetaData customizeMetaData(QInstance instance, QTableMetaData table)
   {
      if(com.kingsrook.qbits.wormaudit.model.WormAuditTables.SETTINGS.equals(table.getName()))
      {
         table.withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_DELETE);
         table.withAuditRules(new com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules()
            .withAuditLevel(com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel.FIELD));
         return (table);
      }
      if(CORE_TABLES.contains(table.getName()) || table.getName().startsWith("worm_audit_"))
      {
         table.withoutCapabilities(Capability.TABLE_UPDATE, Capability.TABLE_DELETE);
      }
      if(table.getName().startsWith("worm_audit_"))
      {
         table.withoutCapabilities(Capability.TABLE_INSERT);
      }
      return (table);
   }


   /*******************************************************************************
    ** Preserve unrelated failures, map only the documented SQLSTATE and prefix.
    *******************************************************************************/
   public static QException map(Exception error)
   {
      for(Throwable cause = error; cause != null; cause = cause.getCause())
      {
         if(cause instanceof SQLException sql && "P0001".equals(sql.getSQLState())
            && sql.getMessage() != null && sql.getMessage().startsWith("worm_audit:"))
         {
            return (new QUserFacingException(MESSAGE));
         }
         // The PostgreSQL driver prepends ERROR: to server error messages.
         if(cause instanceof SQLException sql && "P0001".equals(sql.getSQLState())
            && sql.getMessage() != null && sql.getMessage().startsWith("ERROR: worm_audit:"))
         {
            return (new QUserFacingException(MESSAGE));
         }
      }
      return (error instanceof QException q ? q : new QException("WORM audit operation failed", error));
   }
}
