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

package com.kingsrook.qbits.wormaudit.demo;


import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.PhiCanaryTest;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.WormAuditQBitProducer;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.export.SealedExporter;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.processes.VerificationRuns;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.audits.AuditActionCustomizerInterface;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.instances.AbstractQQQApplication;
import com.kingsrook.qqq.backend.core.instances.QInstanceValidator;
import com.kingsrook.qqq.backend.core.model.actions.audits.AuditSingleInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.audits.AuditsMetaDataProvider;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.audits.AuditLevel;
import com.kingsrook.qqq.backend.core.model.metadata.audits.QAuditRules;
import com.kingsrook.qqq.backend.core.model.metadata.authentication.QAuthenticationMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.PermissionLevel;
import com.kingsrook.qqq.backend.core.model.metadata.permissions.QPermissionRules;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;
import com.kingsrook.qqq.middleware.javalin.QApplicationJavalinServer;


/*******************************************************************************
 ** Local demo: synthetic notes, test HMAC tokens, real chain, checkpoints,
 ** verifications and sealed exports over a moving clock. Memory storage and its
 ** simulated purge are not production enforcement.
 **
 ** <pre>
 ** ./mvnw -o test-compile exec:java -Dexec.classpathScope=test -Dexec.mainClass=com.kingsrook.qbits.wormaudit.demo.WormAuditDemoServer -Dexec.args=8099
 ** </pre>
 *******************************************************************************/
public class WormAuditDemoServer extends AbstractQQQApplication
{
   private static Clock clock = Clock.systemUTC();
   private final MemorySealedStore storage = new MemorySealedStore();
   private WormAuditQBitConfig config;

   /*******************************************************************************
    ** The PhiCanaryTest stand-in, with a moving timestamp before audit insertion.
    *******************************************************************************/
   public static class DemoTokenHook extends PhiCanaryTest.TokenHook
   {
      /*******************************************************************************
       ** Tokenize through the same core customization point as the canary test.
       *******************************************************************************/
      @Override
      public void customizeInput(AuditSingleInput input)
      {
         input.withTimestamp(clock.instant());
         super.customizeInput(input);
      }
   }


   /*******************************************************************************
    ** Fully anonymous demo with a FIELD-audited synthetic note table.
    *******************************************************************************/
   @Override
   public QInstance defineQInstance() throws QException
   {
      try
      {
         var keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
         config = new WormAuditQBitConfig().withBackendName("memory").withCheckpointEveryLinks(20).withCheckpointEveryMinutes(1)
            .withSigningKey(() -> new WormAuditQBitConfig.SigningKey("demo", keys.getPrivate())).withTrustedPublicKeys(Map.of("demo", keys.getPublic()))
            .withSealedStoreSupplier(() -> storage)
            // Synthetic local demo only: anonymous readers can view its tables.
            .withTableMetaDataCustomizer((instance, table) -> table.withPermissionRules(new QPermissionRules().withLevel(PermissionLevel.NOT_PROTECTED)));
         QInstance instance = new QInstance().withInstanceDefaultAuthentication(new QAuthenticationMetaData()
            .withName("anonymous").withType(QAuthenticationType.FULLY_ANONYMOUS));
         instance.addBackend(new QBackendMetaData().withName("memory").withBackendType(MemoryBackendModule.class));
         new AuditsMetaDataProvider().defineAll(instance, "memory", null);
         instance.addTable(new QTableMetaData().withName("patient_note").withLabel("Synthetic patient note").withBackendName("memory")
            .withPrimaryKeyField("id").withRecordLabelFields("id").withRecordLabelFormat("Note #%s")
            .withField(new QFieldMetaData("id", QFieldType.INTEGER))
            .withField(new QFieldMetaData("diagnosis", QFieldType.STRING).withLabel("Diagnosis").withSupplementalMetaData(new PhiCanaryTest.Phi()))
            .withAuditRules(new QAuditRules().withAuditLevel(AuditLevel.FIELD)));
         instance.addSupplementalCustomizer(AuditActionCustomizerInterface.CUSTOMIZER_TYPE, new QCodeReference(DemoTokenHook.class));
         new WormAuditQBitProducer().withQBitConfig(config).produce(instance);
         instance.setHomeAppName(config.getAppName());
         return (instance);
      }
      catch(Exception e)
      {
         throw (new QException("Cannot define WORM Audit demo", e));
      }
   }


   /*******************************************************************************
    ** Write through core DML and the test token hook at the current demo time.
    *******************************************************************************/
   private void notes(int count) throws QException
   {
      for(int i = 0; i < count; i++)
      {
         new InsertAction().execute(new InsertInput("patient_note").withRecord(new QRecord().withValue("diagnosis", "SYNTHETIC-DEMO-NOTE-" + i)));
      }
   }


   /*******************************************************************************
    ** Persist a real verifier result with the historical run time.
    *******************************************************************************/
   private void verify() throws QException
   {
      var result = new WormAuditVerifier(config).verify(null, clock.instant());
      VerificationRuns.save(result, "SCHEDULE", null, clock.instant());
   }


   /*******************************************************************************
    ** Use the production exporter and configured storage boundary.
    *******************************************************************************/
   private void seal() throws QException
   {
      var result = new SealedExporter(config).run("SCHEDULE", clock.instant());
      if(result.failed() || result.row() == null)
      {
         throw (new QException("Demo seeding failed to seal its checkpointed range"));
      }
   }


   /*******************************************************************************
    ** A fortnight of activity and a genuinely expired, sealed prefix.
    *******************************************************************************/
   public void seed(QInstance instance) throws Exception
   {
      QContext.init(instance, new QSession());
      AuditStore store = new AuditStore(null);
      Instant today = Instant.now().minus(Duration.ofHours(2));
      try
      {
         Instant expired = today.atZone(ZoneOffset.UTC).minusYears(7).toInstant();
         clock = Clock.fixed(expired, ZoneOffset.UTC);
         notes(3);
         clock = Clock.fixed(expired.plusSeconds(120), ZoneOffset.UTC);
         new WormAuditChainer(config).chainOnce(clock.instant());
         clock = Clock.fixed(expired.plusSeconds(240), ZoneOffset.UTC);
         new WormAuditChainer(config).chainOnce(clock.instant());
         verify();
         seal();
         QRecord anchor = store.last(WormAuditTables.CHAIN);
         long auditCount = store.count("audit", new QQueryFilter());
         long detailCount = store.count("auditDetail", new QQueryFilter());
         // Demo data: memory has no purge function. Remove the expired, sealed
         // prefix and append the receipt the PostgreSQL function would write.
         for(String table : List.of("auditDetail", "audit", WormAuditTables.CHAIN))
         {
            for(QRecord row : store.all(table))
            {
               MemoryRecordStore.getInstance().delete(new DeleteInput(table).withPrimaryKeys(List.of(row.getValue("id"))));
            }
         }
         store.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("requested_at", today.minus(Duration.ofDays(15)))
            .withValue("requested_by", "demo-purger").withValue("cutoff", expired.plusSeconds(1)).withValue("retention_interval", "6 years")
            .withValue("outcome", "PURGED").withValue("reason", "Expired sealed prefix removed (demo memory purge)")
            .withValue("audits_deleted", auditCount).withValue("details_deleted", detailCount).withValue("links_deleted", anchor.getValueLong("id"))
            .withValue("anchor_link_id", anchor.getValueLong("id")).withValue("anchor_hash", anchor.getValueString("link_hash"))));
         for(int day = 13; day >= 0; day--)
         {
            Instant time = today.minus(Duration.ofDays(day));
            clock = Clock.fixed(time, ZoneOffset.UTC);
            notes(25);
            clock = Clock.fixed(time.plusSeconds(120), ZoneOffset.UTC);
            new WormAuditChainer(config).chainOnce(clock.instant());
            clock = Clock.fixed(time.plusSeconds(240), ZoneOffset.UTC);
            new WormAuditChainer(config).chainOnce(clock.instant());
            if(day == 7)
            {
               // Demo seeding only: temporarily tamper a memory detail, persist a
               // genuine FAIL naming that link, then restore before later PASSes.
               QRecord detail = store.all("auditDetail").getFirst();
               var original = detail.getValue("newValue");
               memoryValue(detail, "hmac:v1:demo:tampered");
               verify();
               memoryValue(detail, original);
            }
            else
            {
               verify();
            }
            seal();
         }
         // Demo REFUSED receipt: too-recent cutoff; no rows removed.
         store.insert(WormAuditTables.PURGE, List.of(new QRecord().withValue("requested_at", today.plusSeconds(300))
            .withValue("requested_by", "demo-purger").withValue("cutoff", today).withValue("retention_interval", "6 years")
            .withValue("outcome", "REFUSED").withValue("reason", "Cutoff is inside the retention interval")
            .withValue("audits_deleted", 0L).withValue("details_deleted", 0L).withValue("links_deleted", 0L)));
         // Real unsealed suffix and unchained backlog; no invented export gap.
         clock = Clock.fixed(today.plusSeconds(600), ZoneOffset.UTC);
         notes(5);
         new WormAuditChainer(config).chainOnce(today.plusSeconds(720));
         clock = Clock.fixed(Instant.now().minusSeconds(120), ZoneOffset.UTC);
         notes(2);
         clock = Clock.systemUTC();
         notes(1);
      }
      finally
      {
         clock = Clock.systemUTC();
         QContext.clear();
      }
   }


   /*******************************************************************************
    ** Deliberate memory-only tamper used solely while seeding the FAIL receipt.
    *******************************************************************************/
   private static void memoryValue(QRecord detail, java.io.Serializable value) throws QException
   {
      MemoryRecordStore.getInstance().update(new UpdateInput("auditDetail").withRecords(List.of(new QRecord()
         .withValue("id", detail.getValue("id")).withValue("newValue", value))), false);
   }


   /*******************************************************************************
    ** Serve the standard widget API and packaged Next UI, reusing the seeded keys.
    *******************************************************************************/
   public static void main(String[] args) throws Exception
   {
      int port = args.length == 0 ? 8099 : Integer.parseInt(args[0]);
      WormAuditDemoServer application = new WormAuditDemoServer();
      QInstance instance = application.defineQInstance();
      new QInstanceValidator().validate(instance);
      application.seed(instance);
      new QApplicationJavalinServer(new AbstractQQQApplication()
      {
         @Override
         public QInstance defineQInstance()
         {
            return (instance);
         }
      }).withPort(port).withServeFrontendNext(true).start();
      System.out.println("WORM Audit demo on http://localhost:" + port + "/app/worm_audit");
   }
}
