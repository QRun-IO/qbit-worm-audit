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


import java.util.List;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qqq.backend.core.actions.dashboard.widgets.AbstractWidgetRenderer;
import com.kingsrook.qqq.backend.core.actions.permissions.CustomPermissionChecker;
import com.kingsrook.qqq.backend.core.actions.permissions.PermissionsHelper;
import com.kingsrook.qqq.backend.core.actions.permissions.TablePermissionSubType;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.model.actions.AbstractActionInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetOutput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.WidgetType;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.dashboard.QWidgetMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppSection;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QIcon;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.MetaDataWithPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** WORM Audit navigation and standard HTML widgets, scoped to this QInstance.
 *******************************************************************************/
public final class WormAuditApp
{
   public static final String HOME_WIDGET = "wormAuditHome";
   public static final String HEALTH_CARD_WIDGET = "wormAuditHealthCard";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WormAuditApp()
   {
   }


   /*******************************************************************************
    ** The home and optional host-dashboard summary share the app's permissions.
    *******************************************************************************/
   public static List<QWidgetMetaData> widgets()
   {
      return (List.of(
         new QWidgetMetaData().withName(HOME_WIDGET).withLabel("Overview").withType(WidgetType.HTML.getType())
            .withCodeReference(new QCodeReference(HomeRenderer.class)).withGridColumns(12).withIsCard(false).withPermissionRules(permissions()),
         new QWidgetMetaData().withName(HEALTH_CARD_WIDGET).withLabel("WORM Audit").withType(WidgetType.HTML.getType())
            .withCodeReference(new QCodeReference(HealthCardRenderer.class)).withGridColumns(12).withIsCard(true).withPermissionRules(permissions())));
   }


   /*******************************************************************************
    ** Home, Verifications, Sealed Exports, Checkpoints, Audit Chain, Purges.
    *******************************************************************************/
   public static QAppMetaData app(WormAuditQBitConfig config, List<QTableMetaData> tables)
   {
      QAppMetaData app = new QAppMetaData().withName(config.getAppName()).withLabel(config.getAppLabel())
         .withIcon(new QIcon("verified_user")).withPermissionRules(permissions()).withWidgets(List.of(HOME_WIDGET));
      app.setParentAppName(config.getParentAppName());
      for(String name : WormAuditTables.NAV)
      {
         QTableMetaData table = tables.stream().filter(t -> t.getName().equals(name)).findFirst().orElseThrow();
         app.withSectionOfChildren(new QAppSection().withName(name).withLabel(WormAuditTables.navigationLabel(name)),
            WormAuditTables.SETTINGS.equals(name) ? table.clone().withLabel("Settings") : table);
      }
      return (app);
   }


   /*******************************************************************************
    ** Read on any WORM table grants the value-free aggregate overview.
    *******************************************************************************/
   public static QPermissionRules permissions()
   {
      return (new QPermissionRules().withLevel(PermissionLevel.HAS_ACCESS_PERMISSION)
         .withCustomPermissionChecker(new QCodeReference(HomePermissionChecker.class)));
   }


   /*******************************************************************************
    ** Honor the host's actual table permission rules, including custom checkers.
    *******************************************************************************/
   public static class HomePermissionChecker implements CustomPermissionChecker
   {
      /*******************************************************************************
       ** Reject direct widget requests unless at least one table is readable.
       *******************************************************************************/
      @Override
      public void checkPermissionsThrowing(AbstractActionInput input, MetaDataWithPermissionRules metadata) throws QPermissionDeniedException
      {
         for(String table : WormAuditTables.ALL)
         {
            try
            {
               PermissionsHelper.checkTablePermissionThrowing(new QueryInput(table), TablePermissionSubType.READ);
               return;
            }
            catch(QPermissionDeniedException expected)
            {
               // Another WORM table may grant access to the aggregate overview.
            }
         }
         throw (new QPermissionDeniedException("Read access to a WORM audit table is required"));
      }
   }


   /*******************************************************************************
    ** Full-width home renderer.
    *******************************************************************************/
   public static class HomeRenderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Render only metadata, counts and value-free reasons.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         new HomePermissionChecker().checkPermissionsThrowing(input, null);
         return (new RenderWidgetOutput(new RawHTML(null, WormAuditHomeView.render(WormAuditHomeData.load(), VerificationRuns.config().getTablePathPrefix()))));
      }
   }


   /*******************************************************************************
    ** Optional compact host dashboard renderer.
    *******************************************************************************/
   public static class HealthCardRenderer extends AbstractWidgetRenderer
   {
      /*******************************************************************************
       ** Link the status summary to the owning app home.
       *******************************************************************************/
      @Override
      public RenderWidgetOutput render(RenderWidgetInput input) throws QException
      {
         new HomePermissionChecker().checkPermissionsThrowing(input, null);
         WormAuditQBitConfig config = VerificationRuns.config();
         String path = config.getTablePathPrefix() + "/" + (config.getParentAppName() == null ? "" : config.getParentAppName() + "/") + config.getAppName();
         return (new RenderWidgetOutput(new RawHTML(config.getAppLabel(), WormAuditHomeView.renderHealthCard(WormAuditHomeData.load(), path))));
      }
   }
}
