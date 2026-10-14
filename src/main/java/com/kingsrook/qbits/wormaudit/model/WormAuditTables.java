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
import com.kingsrook.qbits.wormaudit.WormAuditSettings;
import com.kingsrook.qqq.backend.core.actions.customizers.TableCustomizers;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.help.QHelpContent;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValue;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSource;
import com.kingsrook.qqq.backend.core.model.metadata.possiblevalues.QPossibleValueSourceType;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Capability;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QFieldSection;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.Tier;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;


/*******************************************************************************
 ** Append-only sidecar tables. Snake-case fields map directly to DDL columns.
 ** Labels also supply the standard QQQ app navigation wording.
 *******************************************************************************/
public final class WormAuditTables
{
   public static final String CHAIN = "worm_audit_chain";
   public static final String CHECKPOINT = "worm_audit_checkpoint";
   public static final String EXPORT = "worm_audit_export";
   public static final String VERIFICATION = "worm_audit_verification";
   public static final String PURGE = "worm_audit_purge";
   public static final String SETTINGS = "worm_audit_settings";
   public static final List<String> ALL = List.of(CHAIN, CHECKPOINT, EXPORT, VERIFICATION, PURGE, SETTINGS);
   public static final List<String> NAV = List.of(VERIFICATION, EXPORT, CHECKPOINT, CHAIN, PURGE, SETTINGS);

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
      tables.add(table(config, EXPORT, "Sealed Export", "id:L from_link_id:L to_link_id:L from_checkpoint_id:L to_checkpoint_id:L bucket_alias:S object_prefix:T object_versions:T manifest_key:T manifest_sha256:S prev_manifest_sha256:S object_count:L byte_count:L lock_mode:S retain_until:D sealed_at:D"));
      tables.add(table(config, VERIFICATION, "Verification", "id:L kind:S trigger:S started_at:D finished_at:D from_link_id:L to_link_id:L links_checked:L outcome:S break_count:L first_break_link_id:L first_break_audit_id:L first_break_reason:T export_id:L run_by:S"));
      tables.add(table(config, PURGE, "Purge", "id:L requested_at:D requested_by:S cutoff:D retention_interval:S outcome:S reason:T audits_deleted:L details_deleted:L links_deleted:L anchor_link_id:L anchor_hash:S"));
      tables.add(settings(config));
      return (tables);
   }


   /*******************************************************************************
    ** Editable, FIELD-audited singleton with standard QQQ record sections.
    *******************************************************************************/
   public static QTableMetaData settings(WormAuditQBitConfig config)
   {
      QTableMetaData table = new QTableMetaData().withName(SETTINGS).withLabel("WORM Audit Settings")
         .withBackendName(config.getBackendName()).withBackendDetails(new RDBMSTableBackendDetails().withTableName(SETTINGS))
         .withPrimaryKeyField("id").withRecordLabelFields("id").withRecordLabelFormat("WORM Audit Settings")
         .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.FIELD))
         .withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.READ_INSERT_EDIT_DELETE_PERMISSIONS)
            .withPermissionBaseName(SETTINGS).withCustomPermissionChecker(new QCodeReference(SettingsPermissions.class)))
         .withoutCapabilities(Capability.TABLE_INSERT, Capability.TABLE_DELETE)
         .withCustomizer(TableCustomizers.PRE_INSERT_RECORD, new QCodeReference(SettingsCustomizer.class))
         .withCustomizer(TableCustomizers.PRE_UPDATE_RECORD, new QCodeReference(SettingsCustomizer.class))
         .withCustomizer(TableCustomizers.POST_UPDATE_RECORD, new QCodeReference(SettingsCustomizer.class))
         .withCustomizer(TableCustomizers.PRE_DELETE_RECORD, new QCodeReference(SettingsCustomizer.class))
         .withField(new QFieldMetaData("id", QFieldType.INTEGER).withLabel("ID").withBackendName("id").withIsEditable(false).withDefaultValue(1));
      var defaults = WormAuditSettings.defaults(config);
      table.withField(new QFieldMetaData("audit_retention_years", QFieldType.INTEGER).withBackendName("audit_retention_years").withLabel("Audit retention years")
         .withIsRequired(true).withDefaultValue(defaults.getValue("audit_retention_years")));
      table.withField(new QFieldMetaData("export_lock_mode", QFieldType.STRING).withBackendName("export_lock_mode").withLabel("Export lock mode")
         .withIsRequired(true).withDefaultValue(defaults.getValue("export_lock_mode")));
      table.withField(new QFieldMetaData("export_retention_days", QFieldType.INTEGER).withBackendName("export_retention_days").withLabel("Export retention days")
         .withIsRequired(true).withDefaultValue(defaults.getValue("export_retention_days")));
      table.withField(new QFieldMetaData("checkpoint_every_links", QFieldType.INTEGER).withBackendName("checkpoint_every_links").withLabel("Checkpoint every links")
         .withIsRequired(true).withDefaultValue(defaults.getValue("checkpoint_every_links")));
      table.withField(new QFieldMetaData("checkpoint_every_minutes", QFieldType.INTEGER).withBackendName("checkpoint_every_minutes").withLabel("Checkpoint every minutes")
         .withIsRequired(true).withDefaultValue(defaults.getValue("checkpoint_every_minutes")));
      table.withField(new QFieldMetaData("chain_interval_seconds", QFieldType.INTEGER).withBackendName("chain_interval_seconds").withLabel("Chain interval seconds")
         .withIsRequired(true).withDefaultValue(defaults.getValue("chain_interval_seconds")));
      table.withField(new QFieldMetaData("settle_horizon_seconds", QFieldType.INTEGER).withBackendName("settle_horizon_seconds").withLabel("Settle horizon seconds")
         .withIsRequired(true).withDefaultValue(defaults.getValue("settle_horizon_seconds")));
      table.withField(new QFieldMetaData("late_detail_lookback_hours", QFieldType.INTEGER).withBackendName("late_detail_lookback_hours").withLabel("Late detail lookback hours")
         .withIsRequired(true).withDefaultValue(defaults.getValue("late_detail_lookback_hours")));
      table.withField(new QFieldMetaData("export_cron", QFieldType.STRING).withBackendName("export_cron").withLabel("Export schedule (UTC)")
         .withIsRequired(true).withDefaultValue(defaults.getValue("export_cron")));
      table.withField(new QFieldMetaData("verify_cron", QFieldType.STRING).withBackendName("verify_cron").withLabel("Verify schedule (UTC)")
         .withIsRequired(true).withDefaultValue(defaults.getValue("verify_cron")));
      table.getField("export_lock_mode").withInlinePossibleValueSource(new QPossibleValueSource().withName(SETTINGS + "_lock_mode")
         .withType(QPossibleValueSourceType.ENUM).withIdType(QFieldType.STRING).withEnumValues(List.of(
            new QPossibleValue<>("GOVERNANCE", "GOVERNANCE"), new QPossibleValue<>("COMPLIANCE", "COMPLIANCE"))));
      for(String field : List.of("export_cron", "verify_cron", "chain_interval_seconds"))
      {
         table.getField(field).withHelpContent(new QHelpContent("Takes effect after restart. Cron schedules use UTC and Quartz syntax."));
      }
      table.getField("audit_retention_years").withHelpContent(new QHelpContent("Used for the next eligible purge date. The database purge interval changes only through a reviewed migration."));
      table.withField(new QFieldMetaData("notes", QFieldType.TEXT).withLabel("Notes").withBackendName("notes"));
      table.withField(new QFieldMetaData("modify_date", QFieldType.DATE_TIME).withLabel("Modified").withBackendName("modify_date").withIsEditable(false));
      table.withField(new QFieldMetaData("modified_by", QFieldType.STRING).withLabel("Modified by").withBackendName("modified_by").withIsEditable(false));
      table.withSection(new QFieldSection("retention", "Retention", new QIcon("lock"), Tier.T1,
         List.of("id", "audit_retention_years", "export_lock_mode", "export_retention_days")).withGridColumns(12));
      table.withSection(new QFieldSection("cadence", "Chain and checkpoints", new QIcon("link"), Tier.T2,
         List.of("checkpoint_every_links", "checkpoint_every_minutes", "settle_horizon_seconds", "late_detail_lookback_hours")).withGridColumns(12));
      table.withSection(new QFieldSection("schedules", "Schedules (after restart)", new QIcon("schedule"), Tier.T2,
         List.of("chain_interval_seconds", "export_cron", "verify_cron")).withGridColumns(12));
      table.withSection(new QFieldSection("changes", "Changes", new QIcon("edit_note"), Tier.T2,
         List.of("notes", "modify_date", "modified_by")).withGridColumns(12));
      return (table);
   }


   /*******************************************************************************
    ** Common metadata for a process-written table.
    *******************************************************************************/
   private static QTableMetaData table(WormAuditQBitConfig config, String name, String label, String fields)
   {
      QTableMetaData table = new QTableMetaData().withName(name).withLabel(navigationLabel(name))
         .withBackendName(config.getBackendName()).withBackendDetails(new RDBMSTableBackendDetails().withTableName(name))
         .withPrimaryKeyField("id").withRecordLabelFields("id").withRecordLabelFormat(label + " #%s")
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
         table.withField(new QFieldMetaData(parts[0], type).withBackendName(parts[0]).withLabel(fieldLabel(parts[0])));
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
      switch(name)
      {
         case CHAIN -> table.withRecordLabelFormat("Link #%s");
         case EXPORT -> table.withRecordLabelFormatAndFields("Export #%s (links %s–%s)", "id", "from_link_id", "to_link_id");
         case VERIFICATION, PURGE -> table.withRecordLabelFormatAndFields(label + " #%s (%s)", "id", "outcome");
         default ->
         {
         }
      }
      if(table.getFields().containsKey("kind"))
      {
         table.getField("kind").withInlinePossibleValueSource(new QPossibleValueSource().withName(name + "_kind")
            .withType(QPossibleValueSourceType.ENUM).withIdType(QFieldType.STRING).withEnumValues(List.of(new QPossibleValue<>("AUDIT", "Audit"),
               new QPossibleValue<>("LATE_DETAIL", "Late detail"), new QPossibleValue<>("CHAIN", "Chain"),
               new QPossibleValue<>("SEALED_EXPORT", "Sealed export"))));
      }
      if(table.getFields().containsKey("outcome"))
      {
         table.getField("outcome").withInlinePossibleValueSource(new QPossibleValueSource().withName(name + "_outcome")
            .withType(QPossibleValueSourceType.ENUM).withIdType(QFieldType.STRING).withEnumValues(List.of(new QPossibleValue<>("PASS", "Pass"),
               new QPossibleValue<>("FAIL", "Fail"), new QPossibleValue<>("PURGED", "Purged"), new QPossibleValue<>("REFUSED", "Refused"))));
      }
      if(VERIFICATION.equals(name))
      {
         table.withSection(new QFieldSection("result", "Result", new QIcon("fact_check"), Tier.T2,
            List.of("id", "outcome", "break_count", "first_break_link_id", "first_break_audit_id", "first_break_reason")).withGridColumns(12));
         table.withSection(new QFieldSection("scope", "Scope", new QIcon("link"), Tier.T2,
            List.of("kind", "trigger", "from_link_id", "to_link_id", "links_checked", "export_id")).withGridColumns(12));
         table.withSection(new QFieldSection("run", "Run", new QIcon("schedule"), Tier.T2,
            List.of("started_at", "finished_at", "run_by")).withGridColumns(12));
      }
      else
      {
         table.withSection(new QFieldSection("record", label, new QIcon("fact_check"), Tier.T1,
            new ArrayList<>(table.getFields().keySet())).withGridColumns(12));
      }
      if(List.of(CHECKPOINT, EXPORT, VERIFICATION).contains(name))
      {
         table.withSection(new QFieldSection("links", new QIcon("link"), Tier.T2).withLabel("Chain links")
            .withWidgetName(name + "_links").withGridColumns(12));
      }
      return (table);
   }


   /*******************************************************************************
    ** Core RC.5 shares the table label with its navigation tree node.
    *******************************************************************************/
   public static String navigationLabel(String name)
   {
      return (switch(name)
      {
         case SETTINGS -> "Settings";
         case CHAIN -> "Audit Chain";
         case CHECKPOINT -> "Checkpoints";
         case EXPORT -> "Sealed Exports";
         case VERIFICATION -> "Verifications";
         default -> "Purges";
      });
   }


   /*******************************************************************************
    ** Plain record labels independent of physical column names.
    *******************************************************************************/
   private static String fieldLabel(String name)
   {
      return (switch(name)
      {
         case "id" -> "ID";
         case "kind" -> "Kind";
         case "audit_id" -> "Audit";
         case "detail_ids" -> "Detail ids";
         case "prev_hash" -> "Previous hash";
         case "link_hash" -> "Link hash";
         case "chained_at" -> "Chained";
         case "from_link_id" -> "From link";
         case "to_link_id" -> "To link";
         case "link_count" -> "Links";
         case "head_hash" -> "Head hash";
         case "merkle_root" -> "Merkle root";
         case "algorithm" -> "Algorithm";
         case "key_id" -> "Key ID";
         case "public_key" -> "Public key";
         case "signature" -> "Signature";
         case "created_at" -> "Created";
         case "from_checkpoint_id" -> "From checkpoint";
         case "to_checkpoint_id" -> "To checkpoint";
         case "bucket_alias" -> "Bucket alias";
         case "object_prefix" -> "Object prefix";
         case "object_versions" -> "Object versions";
         case "manifest_key" -> "Manifest key";
         case "manifest_sha256" -> "Manifest SHA-256";
         case "prev_manifest_sha256" -> "Previous manifest SHA-256";
         case "object_count" -> "Objects";
         case "byte_count" -> "Bytes";
         case "lock_mode" -> "Lock mode";
         case "retain_until" -> "Retain until";
         case "sealed_at" -> "Sealed";
         case "trigger" -> "Trigger";
         case "started_at" -> "Started";
         case "finished_at" -> "Finished";
         case "links_checked" -> "Links checked";
         case "outcome" -> "Outcome";
         case "break_count" -> "Breaks";
         case "first_break_link_id" -> "First break link";
         case "first_break_audit_id" -> "First break audit";
         case "first_break_reason" -> "First break";
         case "export_id" -> "Sealed export";
         case "run_by" -> "Run by";
         case "requested_at" -> "Requested";
         case "requested_by" -> "Requested by";
         case "cutoff" -> "Cutoff";
         case "retention_interval" -> "Retention interval";
         case "reason" -> "Reason";
         case "audits_deleted" -> "Audits deleted";
         case "details_deleted" -> "Details deleted";
         case "links_deleted" -> "Links deleted";
         case "anchor_link_id" -> "Anchor link";
         case "anchor_hash" -> "Anchor hash";
         default -> throw new IllegalArgumentException("Missing field label: " + name);
      });
   }
}
