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

package com.kingsrook.qbits.wormaudit.model;


import com.kingsrook.qqq.backend.core.actions.permissions.CustomPermissionChecker;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;


/*******************************************************************************
 ** Reading uses the full table name; editing additionally needs settings access.
 *******************************************************************************/
public class SettingsPermissions implements CustomPermissionChecker
{
   /*******************************************************************************
    ** Enforce table permission and the separate settings permission.
    *******************************************************************************/
   @Override
   public void checkPermissionsThrowing(AbstractActionInput input, MetaDataWithPermissionRules metadata) throws QPermissionDeniedException
   {
      var session = QContext.getQSession();
      boolean edit = input instanceof UpdateInput;
      if(input instanceof InsertInput || input instanceof DeleteInput || session == null
         || !session.hasPermission(WormAuditTables.SETTINGS + (edit ? ".edit" : ".read"))
         || (edit && !session.hasPermission("worm_audit.settings")))
      {
         throw (new QPermissionDeniedException(edit ? "Editing WORM Audit Settings requires worm_audit_settings.edit and worm_audit.settings."
            : "WORM Audit Settings requires read access; adding or deleting settings is not allowed."));
      }
   }
}
