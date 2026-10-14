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


import java.util.ArrayList;
import java.util.List;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QFieldSection;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Tier;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;


/*******************************************************************************
 ** Append-only sidecar tables. Snake-case fields map directly to DDL columns.
 ** Export metadata is the integration hook for phase (b); no export runs here.
 *******************************************************************************/
public final class WormAuditTables
{
   public static final String CHAIN = "worm_audit_chain";
   public static final String CHECKPOINT = "worm_audit_checkpoint";
   public static final String EXPORT = "worm_audit_export";
   public static final String VERIFICATION = "worm_audit_verification";
   public static final String PURGE = "worm_audit_purge";
   public static final List<String> ALL = List.of(CHAIN, CHECKPOINT, EXPORT, VERIFICATION, PURGE);
   public static final List<String> NAV = List.of(VERIFICATION, EXPORT, CHECKPOINT, CHAIN, PURGE);

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WormAuditTables()
   {
   }


   /*******************************************************************************
    ** Construct full record screens, with no recursive audit writes.
    *******************************************************************************/
   public static List<QTableMetaData> tables(WormAuditQBitConfig config)
   {
      List<QTableMetaData> tables = new ArrayList<>();
      tables.add(table(config, CHAIN, "Audit Chain Link", "id:L kind:S audit_id:L detail_ids:T prev_hash:S link_hash:S chained_at:D"));
      tables.add(table(config, CHECKPOINT, "Checkpoint", "id:L from_link_id:L to_link_id:L link_count:L head_hash:S merkle_root:S algorithm:S key_id:S public_key:T signature:T created_at:D"));
      tables.add(table(config, EXPORT, "Sealed Export", "id:L from_link_id:L to_link_id:L from_checkpoint_id:L to_checkpoint_id:L bucket_alias:S object_prefix:T manifest_key:T manifest_sha256:S prev_manifest_sha256:S object_count:L byte_count:L lock_mode:S retain_until:D sealed_at:D"));
      tables.add(table(config, VERIFICATION, "Verification", "id:L kind:S trigger:S started_at:D finished_at:D from_link_id:L to_link_id:L links_checked:L outcome:S break_count:L first_break_link_id:L first_break_audit_id:L first_break_reason:T export_id:L run_by:S"));
      tables.add(table(config, PURGE, "Purge", "id:L requested_at:D requested_by:S cutoff:D retention_interval:S outcome:S reason:T audits_deleted:L details_deleted:L links_deleted:L anchor_link_id:L anchor_hash:S"));
      return (tables);
   }


   /*******************************************************************************
    ** Common metadata for a process-written table.
    *******************************************************************************/
   private static QTableMetaData table(WormAuditQBitConfig config, String name, String label, String fields)
   {
      QTableMetaData table = new QTableMetaData().withName(name).withLabel(label)
         .withBackendName(config.getBackendName()).withBackendDetails(new RDBMSTableBackendDetails().withTableName(name))
         .withPrimaryKeyField("id").withRecordLabelFields("id").withRecordLabelFormat("%s")
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.NONE))
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS).withPermissionBaseName(name));
      for(String spec : fields.split(" "))
      {
         String[] parts = spec.split(":");
         QFieldType type = switch(parts[1])
         {
            case "L" -> QFieldType.LONG;
            case "D" -> QFieldType.DATE_TIME;
            case "T" -> QFieldType.TEXT;
            default -> QFieldType.STRING;
         };
         table.withField(new QFieldMetaData(parts[0], type).withBackendName(parts[0]));
      }
      for(String reference : List.of("from_link_id", "to_link_id", "first_break_link_id", "anchor_link_id"))
      {
         if(table.getFields().containsKey(reference))
         {
            table.getField(reference).withPossibleValueSourceName(CHAIN);
         }
      }
      for(String reference : List.of("from_checkpoint_id", "to_checkpoint_id"))
      {
         if(table.getFields().containsKey(reference))
         {
            table.getField(reference).withPossibleValueSourceName(CHECKPOINT);
         }
      }
      if(table.getFields().containsKey("export_id"))
      {
         table.getField("export_id").withPossibleValueSourceName(EXPORT);
      }
      table.withSection(new QFieldSection("record", label, new QIcon("fact_check"), Tier.T1, new ArrayList<>(table.getFields().keySet())));
      if(List.of(CHECKPOINT, EXPORT, VERIFICATION).contains(name))
      {
         table.withSection(new QFieldSection("links", new QIcon("link"), Tier.T2).withLabel("Chain links").withWidgetName(name + "_links"));
      }
      return (table);
   }
}
