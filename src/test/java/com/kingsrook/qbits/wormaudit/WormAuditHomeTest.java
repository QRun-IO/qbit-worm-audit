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


import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.kingsrook.qbits.objectstorage.api.CapabilityStatus;
import com.kingsrook.qbits.wormaudit.app.WormAuditApp;
import com.kingsrook.qbits.wormaudit.app.WormAuditHomeData;
import com.kingsrook.qbits.wormaudit.app.WormAuditHomeView;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.demo.MemorySealedStore;
import com.kingsrook.qbits.wormaudit.demo.WormAuditDemoServer;
import com.kingsrook.qbits.wormaudit.export.SealedExportVerifier;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qbits.wormaudit.verify.VerificationResult;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QPermissionDeniedException;
import com.kingsrook.qqq.backend.core.instances.QInstanceValidator;
import com.kingsrook.qqq.backend.core.model.actions.widgets.RenderWidgetInput;
import com.kingsrook.qqq.backend.core.model.dashboard.widgets.RawHTML;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.layout.QAppMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.OLD;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.lookups;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.tamper;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


/*******************************************************************************
 ** Home acceptance: truthful summaries, permissions, privacy and real demo data.
 *******************************************************************************/
class WormAuditHomeTest
{
   /*******************************************************************************
    ** Empty tables do not imply successful verification or export coverage.
    *******************************************************************************/
   @Test
   void emptyStatesAndWarnings() throws Exception
   {
      var config = new WormAuditQBitConfig();
      init(config);
      var data = WormAuditHomeData.load(config, new MemorySealedStore(), OLD);
      assertThat(data.links()).isZero();
      assertThat(data.backlog()).isZero();
      assertThat(data.settling()).isZero();
      assertThat(data.anchor()).isNull();
      assertThat(data.oldestAudit()).isNull();
      assertThat(data.nextPurge()).isNull();
      assertThat(data.exportAgeHours()).isNull();
      assertThat(data.warnings()).contains("No signing key configured", "No trusted public keys configured", "Daily verification has never run");
      String html = WormAuditHomeView.render(data, "/app");
      assertThat(html).contains("Chain status", "Export status", "Retention", "Recent purges", "Setup warnings",
         "No links chained yet", "No verification has run yet", "Unknown until verification runs", "No sealed exports yet",
         "No sealed ranges to check", "No live audits", "No purge requests yet");
      assertThat(WormAuditHomeView.renderHealthCard(data, "/app/worm_audit")).contains("Not verified yet");
   }


   /*******************************************************************************
    ** Strict settle boundary and AUDIT anti-join, including late-detail links.
    *******************************************************************************/
   @Test
   void chainBacklogRetentionAndRealFailureRecovery() throws Exception
   {
      var config = ChainVerificationTest.signed();
      init(config);
      audit(1);
      detail(1, 1);
      Instant now = OLD.plusSeconds(120);
      new WormAuditChainer(config).chainOnce(now);
      audit(2);
      audit(3);
      tamper("audit", 3, "timestamp", now.minusSeconds(60));
      var data = WormAuditHomeData.load(config, new MemorySealedStore(), now);
      assertThat(data.links()).isEqualTo(1);
      assertThat(data.lastLinkAt()).isEqualTo(now);
      assertThat(data.backlog()).isEqualTo(1);
      assertThat(data.settling()).isEqualTo(1);
      assertThat(data.oldestAudit()).isEqualTo(OLD.plusSeconds(1));
      assertThat(data.nextPurge()).isEqualTo(OLD.plusSeconds(1).atZone(ZoneOffset.UTC).plusYears(6).toInstant());
      new WormAuditChainer(config).chainOnce(now.plusSeconds(61));
      tamper("auditDetail", 1, "newValue", "forced mismatch");
      var failure = new WormAuditVerifier(config).verify(null, now.plusSeconds(61));
      QRecord failed = VerificationRuns.save(failure, "SCHEDULE", null, now.plusSeconds(62));
      assertThat(failure.passed()).isFalse();
      data = WormAuditHomeData.load(config, new MemorySealedStore(), now.plusSeconds(63));
      assertThat(data.openBreak().getValueLong("id")).isEqualTo(failed.getValueLong("id"));
      String html = WormAuditHomeView.render(data, "/app/admin/worm");
      assertThat(html).contains("/app/admin/worm/worm_audit_verification/1", "/app/admin/worm/worm_audit_chain/1", "content differs from the chained hash");
      assertThat(WormAuditHomeView.renderHealthCard(data, "/app/worm_audit")).contains("Chain breaks reported");
      // A passing selected run must not clear a full-chain failure.
      VerificationRuns.save(new WormAuditVerifier(config).verify(Set.of(2L), now.plusSeconds(64)), "USER", null, now.plusSeconds(65));
      assertThat(WormAuditHomeData.load(config, new MemorySealedStore(), now.plusSeconds(66)).openBreak()).isNotNull();
      tamper("auditDetail", 1, "newValue", "new");
      VerificationRuns.save(new WormAuditVerifier(config).verify(null, now.plusSeconds(67)), "SCHEDULE", null, now.plusSeconds(68));
      data = WormAuditHomeData.load(config, new MemorySealedStore(), now.plusSeconds(69));
      assertThat(data.openBreak()).isNull();
      assertThat(data.warnings()).hasSize(2);
      assertThat(WormAuditHomeView.render(data, "/app")).contains("Setup warnings", "GOVERNANCE", "30 days");
      assertThat(WormAuditHomeView.renderHealthCard(data, "/app/worm_audit")).contains("Setup needs attention");
   }


   /*******************************************************************************
    ** Genuine exports, trailing lag and a corruption fixture for a coverage hole.
    *******************************************************************************/
   @Test
   void sealedRangesLagGapsAndPurges() throws Exception
   {
      var storage = new MemorySealedStore();
      var config = ChainVerificationTest.signed().withSealedStoreSupplier(() -> storage);
      init(config);
      for(long id = 1; id <= 4; id++)
      {
         audit(id);
      }
      Instant now = OLD.plusSeconds(180);
      new WormAuditChainer(config).chainOnce(now);
      var export = new SealedExporter(config).run("USER", now);
      assertThat(export.failed()).isFalse();
      assertThat(new SealedExportVerifier(config).verify(export.row(), "USER").result().passed()).isTrue();
      audit(5);
      new WormAuditChainer(config).chainOnce(now.plusSeconds(120));
      var data = WormAuditHomeData.load(config, null, now.plus(Duration.ofHours(3)));
      assertThat(data.exportLag()).isEqualTo(1);
      assertThat(data.exportAgeHours()).isEqualTo(3);
      assertThat(data.exportGaps()).isEmpty();
      assertThat(data.lockCapability()).isEqualTo("SUPPORTED");
      assertThat(data.bucketAlias()).isEqualTo("worm_audit");
      assertThat(data.lastExport().getValueString("lock_mode")).isEqualTo("GOVERNANCE");
      assertThat(WormAuditHomeView.render(data, "/app")).contains("/app/worm_audit_export/1", "GOVERNANCE", "Retain until");
      // Corruption fixture only: the real exporter never creates this hole.
      tamper(WormAuditTables.EXPORT, 1, "from_link_id", 3L);
      assertThat(WormAuditHomeData.load(config, storage, now).exportGaps()).containsExactly("1–2");
      for(long id = 1; id <= 12; id++)
      {
         STORE.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("id", id).withValue("requested_at", now.plusSeconds(id))
            .withValue("requested_by", "<operator>").withValue("cutoff", OLD).withValue("outcome", id == 1 ? "PURGED" : "REFUSED")
            .withValue("reason", "Retention not elapsed").withValue("anchor_link_id", 2L).withValue("anchor_hash", "abcd".repeat(16))
            .withValue("audits_deleted", 0L).withValue("details_deleted", 0L).withValue("links_deleted", 0L)));
      }
      data = WormAuditHomeData.load(config, storage, now.plusSeconds(20));
      assertThat(data.anchor().getValueLong("anchor_link_id")).isEqualTo(2);
      assertThat(data.recentPurges()).hasSize(10).extracting(r -> r.getValueLong("id")).containsExactly(12L, 11L, 10L, 9L, 8L, 7L, 6L, 5L, 4L, 3L);
      assertThat(data.exportGaps()).isEmpty();
      assertThat(WormAuditHomeView.render(data, "/app")).contains("abcdabcdabcd…", "&lt;operator&gt;", "REFUSED").doesNotContain("abcd".repeat(16));
   }


   /*******************************************************************************
    ** Unknown/unsupported capability and stale schedule diagnostics stay value-free.
    *******************************************************************************/
   @Test
   void capabilityAndDailyWarnings() throws Exception
   {
      var config = ChainVerificationTest.signed();
      init(config);
      var unsupported = new MemorySealedStore()
      {
         @Override
         public boolean supportsLock()
         {
            return (false);
         }
      };
      var unknown = new MemorySealedStore()
      {
         @Override
         public CapabilityStatus lockCapability()
         {
            return (CapabilityStatus.UNKNOWN);
         }
      };
      var error = new MemorySealedStore()
      {
         @Override
         public boolean supportsLock()
         {
            throw (new IllegalStateException("CANARY-provider-secret"));
         }
      };
      assertThat(WormAuditHomeData.load(config, unsupported, OLD).lockCapability()).isEqualTo("UNSUPPORTED");
      assertThat(WormAuditHomeData.load(config, unknown, OLD).lockCapability()).isEqualTo("UNKNOWN");
      String html = WormAuditHomeView.render(WormAuditHomeData.load(config, error, OLD), "/app");
      assertThat(html).contains("UNKNOWN", "Object Lock capability check failed").doesNotContain("CANARY", "provider-secret");
      VerificationRuns.save(new VerificationResult(OLD), "SCHEDULE", null, OLD);
      assertThat(WormAuditHomeData.load(config, unsupported, OLD.plus(Duration.ofHours(26))).warnings()).doesNotContain("Daily verification last ran more than 26 hours ago");
      var stale = WormAuditHomeData.load(config, unsupported, OLD.plus(Duration.ofHours(26)).plusSeconds(1));
      assertThat(stale.warnings()).contains("Daily verification last ran more than 26 hours ago");
      assertThat(WormAuditHomeView.renderHealthCard(stale, "/app/worm_audit")).contains("Setup needs attention");
      config.withTrustedPublicKeys(Map.of());
      assertThat(WormAuditHomeData.load(config, unsupported, OLD).warnings()).contains("No trusted public keys configured");
      // USER and SEALED_EXPORT runs cannot refresh the daily CHAIN heartbeat.
      VerificationRuns.save(new VerificationResult(OLD.plus(Duration.ofDays(2))), "USER", null, OLD.plus(Duration.ofDays(2)));
      VerificationRuns.save(new VerificationResult(OLD.plus(Duration.ofDays(2))), "SCHEDULE", 1L, OLD.plus(Duration.ofDays(2)));
      assertThat(WormAuditHomeData.load(config, unsupported, OLD.plus(Duration.ofDays(2))).warnings()).contains("Daily verification last ran more than 26 hours ago");
   }


   /*******************************************************************************
    ** No portion of raw audit content belongs in either HTML widget.
    *******************************************************************************/
   @Test
   void canaryNeverAppearsAndWidgetsRequireReadPermission() throws Exception
   {
      var config = ChainVerificationTest.signed().withAppName("evidence").withAppLabel("Evidence").withTablePathPrefix("/app");
      var instance = init(config);
      instance.addApp(new QAppMetaData().withName("admin").withLabel("Admin"));
      config.withParentAppName("admin");
      instance.getApp("evidence").setParentAppName("admin");
      String canary = "CANARY-PHI-" + UUID.randomUUID();
      audit(1);
      detail(1, 1);
      tamper("audit", 1, "message", canary);
      tamper("auditDetail", 1, "message", canary);
      tamper("auditDetail", 1, "oldValue", canary);
      tamper("auditDetail", 1, "newValue", canary);
      new WormAuditChainer(config).chainOnce();
      var input = new RenderWidgetInput().withWidgetMetaData(instance.getWidget(WormAuditApp.HOME_WIDGET));
      assertThatThrownBy(() -> new WormAuditApp.HomeRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> new WormAuditApp.HealthCardRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
      QContext.getQSession().withPermissions(WormAuditTables.PURGE + ".read");
      String home = ((RawHTML) new WormAuditApp.HomeRenderer().render(input).getWidgetData()).getHtml();
      String card = ((RawHTML) new WormAuditApp.HealthCardRenderer().render(input).getWidgetData()).getHtml();
      for(int start = 0; start <= canary.length() - 5; start++)
      {
         assertThat(home + card).doesNotContain(canary.substring(start, start + 5));
      }
      assertThat(home + card).contains("overflow-wrap:anywhere", "color:inherit").doesNotContain("overflow-x", "<table", "#fff");
      assertThat(card).contains("href=\"/app/admin/evidence\"");
      assertThat(instance.getApp("evidence").getLabel()).isEqualTo("Evidence");
      assertThat(instance.getApp("evidence").getParentAppName()).isEqualTo("admin");
      assertThat(instance.getApp("evidence").getWidgets()).containsExactly(WormAuditApp.HOME_WIDGET);
      assertThat(instance.getApp("evidence").getChildren()).extracting(c -> c.getName()).containsExactlyElementsOf(WormAuditTables.NAV);
      assertThat(instance.getApp("evidence").getChildren()).extracting(c -> c.getLabel())
         .containsExactly("Verifications", "Sealed Exports", "Checkpoints", "Audit Chain", "Detail Coverage", "Purges", "Settings");
      assertThat(instance.getWidget(WormAuditApp.HOME_WIDGET).getGridColumns()).isEqualTo(12);
      assertThat(instance.getWidget(WormAuditApp.HOME_WIDGET).getIsCard()).isFalse();
      assertThat(instance.getWidget(WormAuditApp.HEALTH_CARD_WIDGET).getIsCard()).isTrue();
      new QInstanceValidator().validate(instance);
   }


   /*******************************************************************************
    ** Embedded widgets retain direct authorization without a standalone app.
    *******************************************************************************/
   @Test
   void embeddedWidgetsRequireReadPermission() throws Exception
   {
      var config = ChainVerificationTest.signed().withIncludeApp(false).withAppName("audit").withAppLabel("Audit");
      var instance = init(config);
      assertThat(instance.getApp("worm_audit")).isNull();
      assertThat(instance.getApp("audit")).isNull();
      var input = new RenderWidgetInput().withWidgetMetaData(instance.getWidget(WormAuditApp.HEALTH_CARD_WIDGET));
      QContext.getQSession().withPermissions("admin.hasAccess");
      assertThatThrownBy(() -> new WormAuditApp.HealthCardRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
      assertThatThrownBy(() -> new WormAuditApp.HomeRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
      QContext.getQSession().withPermissions(WormAuditTables.CHAIN + ".read");
      String card = ((RawHTML) new WormAuditApp.HealthCardRenderer().render(input).getWidgetData()).getHtml();
      assertThat(card).contains("href=\"/app/audit\"");
      assertThat(new WormAuditApp.HomeRenderer().render(input).getWidgetData()).isInstanceOf(RawHTML.class);
      QContext.setQSession(new QSession());
      assertThatThrownBy(() -> new WormAuditApp.HealthCardRenderer().render(input)).isInstanceOf(QPermissionDeniedException.class);
   }


   /*******************************************************************************
    ** Exercise the real SQL anti-join without Docker, including its exact boundary.
    *******************************************************************************/
   @Test
   void sqlSummaryUsesTheWriterAntiJoin() throws Exception
   {
      String url = "jdbc:h2:mem:home_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE;INIT=SET TIME ZONE 'UTC'";
      var config = ChainVerificationTest.signed();
      var instance = RdbmsTestSupport.instance(url, "sa", "", config, false);
      try(var connection = DriverManager.getConnection(url, "sa", ""))
      {
         RdbmsTestSupport.createTables(connection, instance, false);
         QContext.init(instance, new QSession());
         lookups();
         audit(1);
         new WormAuditChainer(config).chainOnce(OLD.plusSeconds(100));
         audit(2);
         audit(3);
         var data = WormAuditHomeData.load(config, new MemorySealedStore(), OLD.plusSeconds(63));
         assertThat(data.links()).isEqualTo(1);
         assertThat(data.backlog()).isEqualTo(1);
         assertThat(data.settling()).isEqualTo(1);
         assertThat(data.warnings()).contains("Daily verification has never run");
      }
   }


   /*******************************************************************************
    ** The demo's history comes from real engines, including FAIL, recovery and PHI tokens.
    *******************************************************************************/
   @Test
   void demoSeedsRealHistory() throws Exception
   {
      MemoryRecordStore.fullReset();
      var application = new WormAuditDemoServer();
      var instance = application.defineQInstance();
      new QInstanceValidator().validate(instance);
      application.seed(instance);
      QContext.init(instance, new QSession());
      var data = WormAuditHomeData.load();
      assertThat(data.links()).isGreaterThanOrEqualTo(350);
      assertThat(data.lastVerification().getValueString("outcome")).isEqualTo("PASS");
      assertThat(data.openBreak()).isNull();
      assertThat(data.exportGaps()).isEmpty();
      assertThat(data.exportLag()).isEqualTo(5);
      assertThat(data.backlog()).isEqualTo(2);
      assertThat(data.settling()).isEqualTo(1);
      assertThat(data.warnings()).hasSize(2);
      assertThat(data.recentPurges()).extracting(r -> r.getValueString("outcome")).containsExactly("REFUSED", "PURGED");
      assertThat(STORE.where(WormAuditTables.VERIFICATION, "outcome", "FAIL")).hasSize(1).allSatisfy(row ->
      {
         assertThat(row.getValueLong("first_break_link_id")).isPositive();
         assertThat(row.getValueLong("first_break_audit_id")).isPositive();
      });
      assertThat(STORE.all("auditDetail")).filteredOn(r -> "diagnosis".equals(r.getValueString("fieldName")))
         .isNotEmpty().allSatisfy(row -> assertThat(row.getValueString("newValue")).startsWith("hmac:v1:test:"));
      var config = VerificationRuns.config();
      // Settle and chain the final backlog before checking the entire live suffix.
      new WormAuditChainer(config).chainOnce(Instant.now().plusSeconds(120));
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
      assertThat(new SealedExportVerifier(config).verify(STORE.last(WormAuditTables.EXPORT), "USER").result().passed()).isTrue();
   }
}
