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


import java.time.Instant;
import java.util.List;
import java.util.Optional;
import com.kingsrook.qbits.wormaudit.WormAuditSettings;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizerInterface;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.actions.permissions.TablePermissionSubType;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QUserFacingException;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Validate the editable singleton, including internal insert-only seeds.
 *******************************************************************************/
public class SettingsCustomizer implements TableCustomizerInterface
{
   /*******************************************************************************
    ** Only the fixed singleton may be inserted by the internal seed path.
    *******************************************************************************/
   @Override
   public List<QRecord> preInsert(InsertInput input, List<QRecord> records, boolean preview) throws QException
   {
      if(records.size() != 1 || !Integer.valueOf(1).equals(records.getFirst().getValueInteger("id")))
      {
         throw (new QUserFacingException("WORM Audit Settings has one row only (ID 1)."));
      }
      if(new com.kingsrook.qbits.wormaudit.chain.AuditStore(input.getTransaction()).get(WormAuditTables.SETTINGS, 1) != null)
      {
         throw (new QUserFacingException("WORM Audit Settings already exists. Edit record 1 instead of adding another record."));
      }
      return (validate(records));
   }


   /*******************************************************************************
    ** Validate partial edits without replacing the existing settings.
    *******************************************************************************/
   @Override
   public List<QRecord> preUpdate(UpdateInput input, List<QRecord> records, boolean preview, Optional<List<QRecord>> oldRecords) throws QException
   {
      PermissionsHelper.checkTablePermissionThrowing(input, TablePermissionSubType.EDIT);
      return (validate(records));
   }


   /*******************************************************************************
    ** Reject deletion even for direct core calls where capability checks are off.
    *******************************************************************************/
   @Override
   public List<QRecord> preDelete(DeleteInput input, List<QRecord> records, boolean preview) throws QException
   {
      throw (new QUserFacingException("WORM Audit Settings cannot be deleted."));
   }


   /*******************************************************************************
    ** Refresh local settings after persistence; remote JVMs retain the bounded cache.
    *******************************************************************************/
   @Override
   public List<QRecord> postUpdate(UpdateInput input, List<QRecord> records, Optional<List<QRecord>> oldRecords) throws QException
   {
      com.kingsrook.qbits.wormaudit.processes.VerificationRuns.config().invalidateSettings();
      return (records);
   }


   /*******************************************************************************
    ** Stamp the editor and time on every valid write; core writes FIELD audits.
    *******************************************************************************/
   private List<QRecord> validate(List<QRecord> records) throws QException
   {
      for(QRecord row : records)
      {
         try
         {
            WormAuditSettings.validate(row);
         }
         catch(IllegalArgumentException e)
         {
            throw (new QUserFacingException(e.getMessage()));
         }
         row.setValue("modify_date", Instant.now());
         row.setValue("modified_by", QContext.getQSession() == null || QContext.getQSession().getUser() == null
            ? "system" : QContext.getQSession().getUser().getIdReference());
      }
      return (records);
   }
}
