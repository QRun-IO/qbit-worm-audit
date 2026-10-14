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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.LinkRangeWidget;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qqq.backend.core.actions.tables.listeners.RecordChangeEvent;
import com.kingsrook.qqq.backend.core.actions.tables.listeners.RecordChangeListenerInterface;
import com.kingsrook.qqq.backend.core.actions.tables.listeners.RecordChangeType;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.ChildRecordListData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Tests and fixtures for record integration test.
 *******************************************************************************/
class RecordIntegrationTest
{
   /*******************************************************************************
    ** All record screens have readable labels and full-width sections and lists.
    *******************************************************************************/
   @Test
   void recordScreensHaveReadableLabelsAndFullWidthLists() throws Exception
   {
      var instance = init(new WormAuditQBitConfig());
      Map<String, String> formats = Map.of(
         WormAuditTables.CHAIN, "Link #%s", WormAuditTables.CHECKPOINT, "Checkpoint #%s",
         WormAuditTables.EXPORT, "Export #%s (links %s–%s)", WormAuditTables.VERIFICATION, "Verification #%s (%s)",
         WormAuditTables.PURGE, "Purge #%s (%s)");
      for(String name : WormAuditTables.ALL)
      {
         var table = instance.getTable(name);
         assertThat(table.getRecordLabelFormat()).isEqualTo(formats.get(name));
         assertThat(table.getRecordLabelFields()).allMatch(table.getFields()::containsKey);
         table.getFields().forEach((fieldName, field) ->
            assertThat(field.getLabel()).as(name + "." + fieldName).isNotBlank().isNotEqualTo(fieldName).doesNotContain("_"));
         table.getSections().forEach(section ->
         {
            assertThat(section.getGridColumns()).isEqualTo(12);
            if(section.getWidgetName() != null)
            {
               assertThat(instance.getWidget(section.getWidgetName()).getGridColumns()).isEqualTo(12);
            }
         });
      }
      assertThat(instance.getTable(WormAuditTables.EXPORT).getRecordLabelFields()).containsExactly("id", "from_link_id", "to_link_id");
      for(String name : List.of(WormAuditTables.VERIFICATION, WormAuditTables.PURGE))
      {
         assertThat(instance.getTable(name).getRecordLabelFields()).containsExactly("id", "outcome");
      }
      var verification = instance.getTable(WormAuditTables.VERIFICATION);
      assertThat(verification.getSections()).extracting(section -> section.getLabel()).containsExactly("Result", "Scope", "Run", "Chain links");
      assertThat(verification.getSections().stream().filter(section -> section.getWidgetName() == null)
         .flatMap(section -> section.getFieldNames().stream()).toList()).containsExactlyInAnyOrderElementsOf(verification.getFields().keySet());
   }


   /*******************************************************************************
    ** Tests and fixtures for event sink.
    *******************************************************************************/
   public static class EventSink implements RecordChangeListenerInterface
   {
      static List<String> tables = new ArrayList<>();

      /*******************************************************************************
       ** Verify applies to.
       *******************************************************************************/
      public boolean appliesTo(String table, RecordChangeType type)
      {
         return (List.of(WormAuditTables.VERIFICATION, WormAuditTables.EXPORT).contains(table)
               && type == RecordChangeType.INSERT);
      }

      /*******************************************************************************
       ** Verify on records changed.
       *******************************************************************************/
      public void onRecordsChanged(RecordChangeEvent event)
      {
         tables.add(event.getTableName());
      }
   }

   /*******************************************************************************
    ** Verify checkpoint child list uses range and read permissions.
    *******************************************************************************/
   @Test
   void checkpointChildListUsesRangeAndReadPermissions() throws Exception
   {
      var config = ChainVerificationTest.signed().withCheckpointEveryLinks(2);
      var instance = init(config);
      audit(1);
      audit(2);
      new WormAuditChainer(config).chainOnce();
      var input =
            new RenderWidgetInput()
                  .withWidgetMetaData(
                        instance.getWidget(WormAuditTables.CHECKPOINT + "_links"));
      input.setQueryParams(Map.of("id", "1"));
      assertThatThrownBy(() -> new LinkRangeWidget().render(input)).isInstanceOf(Exception.class);
      QContext.getQSession()
            .withPermissions("worm_audit_checkpoint.read", "worm_audit_chain.read");
      var data = (ChildRecordListData) new LinkRangeWidget().render(input).getWidgetData();
      assertThat(data.getTotalRows()).isEqualTo(2);
      assertThat(data.getQueryOutput().getRecords()).hasSize(2);
      assertThat(data.getViewAllLink()).contains("filter=");
      String json = com.kingsrook.qqq.backend.core.utils.JsonUtils.toJson(data);
      assertThat(json).contains("Chain links").doesNotContain("signingKey", "trustedPublicKeys", "sealedStoreSupplier", "privateKey");
      input.setQueryParams(Map.of("id", "999"));
      assertThatThrownBy(() -> new LinkRangeWidget().render(input))
            .hasMessageContaining("was not found");
      assertThat(
                  instance.getTable(WormAuditTables.EXPORT)
                        .getField("from_checkpoint_id")
                        .getPossibleValueSourceName())
            .isEqualTo(WormAuditTables.CHECKPOINT);
      assertThat(
                  instance.getTable(WormAuditTables.VERIFICATION)
                        .getField("export_id")
                        .getPossibleValueSourceName())
            .isEqualTo(WormAuditTables.EXPORT);
   }

   /*******************************************************************************
    ** Verify verification inserts reach core event spi for host esb publications.
    *******************************************************************************/
   @Test
   void verificationInsertsReachCoreEventSpiForHostEsbPublications() throws Exception
   {
      var instance = init(new WormAuditQBitConfig());
      EventSink.tables.clear();
      instance.withRecordChangeListener(new QCodeReference(EventSink.class));
      audit(1);
      new WormAuditChainer(VerificationRuns.config()).chainOnce();
      VerificationRuns.run(null, "USER");
      assertThat(EventSink.tables).containsExactly(WormAuditTables.VERIFICATION);
   }
}
