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


import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionEnforcement;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.GetAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QNotFoundException;
import com.kingsrook.qqq.backend.core.model.actions.tables.QInputSource;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.get.GetInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.ChildRecordListData;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.utils.JsonUtils;


/*******************************************************************************
 ** A standard child-record list for a checkpoint/export/verification link range.
 ** This is a record-screen relation, not an app-home widget. Reads retain user
 ** permissions and use a bounded page with a filtered View All link.
 *******************************************************************************/
public class LinkRangeWidget extends AbstractWidgetRenderer
{
   /*******************************************************************************
    ** Render the inclusive range stored on the parent record.
    *******************************************************************************/
   @Override
   public RenderWidgetOutput render(RenderWidgetInput input) throws QException
   {
      String parent = (String) input.getWidgetMetaData().getDefaultValues().get("parentTable");
      GetInput get = new GetInput().withPrimaryKey(input.getQueryParams().get("id")).withInputSource(QInputSource.USER);
      get.setTableName(parent);
      get.withPermissionEnforcement(PermissionEnforcement.ENFORCE);
      QRecord record = new GetAction().execute(get).getRecord();
      if(record == null)
      {
         throw (new QNotFoundException("Audit range record was not found"));
      }
      Long from = record.getValueLong("from_link_id");
      Long to = record.getValueLong("to_link_id");
      QQueryFilter filter = new QQueryFilter()
         .withCriteria(new QFilterCriteria("id", QCriteriaOperator.GREATER_THAN_OR_EQUALS, from == null ? 1L : from))
         .withCriteria(new QFilterCriteria("id", QCriteriaOperator.LESS_THAN_OR_EQUALS, to == null ? 0L : to))
         .withOrderBy(new QFilterOrderBy("id", true));
      CountInput count = new CountInput(WormAuditTables.CHAIN).withFilter(filter).withInputSource(QInputSource.USER);
      count.withPermissionEnforcement(PermissionEnforcement.ENFORCE);
      int total = new CountAction().execute(count).getCount();
      String path = QContext.getQInstance().getTablePath(WormAuditTables.CHAIN);
      String viewAll = path + "?filter=" + URLEncoder.encode(JsonUtils.toJson(filter), StandardCharsets.UTF_8);
      QueryInput query = new QueryInput(WormAuditTables.CHAIN).withFilter(filter.clone().withLimit(100)).withInputSource(QInputSource.USER);
      query.withShouldTranslatePossibleValues(true);
      query.withPermissionEnforcement(PermissionEnforcement.ENFORCE);
      return (new RenderWidgetOutput(new ChildRecordListData("Chain links", new QueryAction().execute(query),
         QContext.getQInstance().getTable(WormAuditTables.CHAIN), path, viewAll, total)));
   }
}
