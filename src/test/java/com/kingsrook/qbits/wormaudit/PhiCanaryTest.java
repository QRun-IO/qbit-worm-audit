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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qbits.wormaudit.chain.WormAuditChainer;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier;
import com.kingsrook.qqq.backend.core.actions.audits.AuditAction;
import com.kingsrook.qqq.backend.core.actions.audits.AuditActionCustomizerInterface;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.audits.AuditInput;
import com.kingsrook.qqq.backend.core.model.actions.audits.AuditSingleInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QSupplementalFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.OLD;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.STORE;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.audit;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.core;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.detail;
import static com.kingsrook.qbits.wormaudit.WormAuditTestSupport.init;
import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 ** Tests and fixtures for phi canary test.
 *******************************************************************************/
public class PhiCanaryTest
{
   // RC.5 has AiFieldMetaData but not DataClassification; use a test-local marker.
   /*******************************************************************************
    ** Tests and fixtures for phi.
    *******************************************************************************/
   public static class Phi extends QSupplementalFieldMetaData
   {
      /*******************************************************************************
       ** Verify get type.
       *******************************************************************************/
      public String getType()
      {
         return ("test-phi");
      }
   }

   // Real RC.5 AuditAction customization point: rewrite details BEFORE insertion.
   /*******************************************************************************
    ** Tests and fixtures for token hook.
    *******************************************************************************/
   public static class TokenHook implements AuditActionCustomizerInterface
   {
      /*******************************************************************************
       ** Verify customize input.
       *******************************************************************************/
      public void customizeInput(AuditSingleInput input)
      {
         for(QRecord detail : input.getDetails())
         {
            var field =
                  QContext.getQInstance()
                        .getTable(input.getAuditTableName())
                        .getField(detail.getValueString("fieldName"));
            if(field.getSupplementalMetaData("test-phi") != null)
            {
               for(String column : List.of("oldValue", "newValue"))
               {
                  if(detail.getValueString(column) == null)
                  {
                     continue;
                  }
                  try
                  {
                     Mac mac = Mac.getInstance("HmacSHA256");
                     mac.init(
                           new SecretKeySpec(
                                 "fixture-key-not-production"
                                       .getBytes(StandardCharsets.UTF_8),
                                 "HmacSHA256"));
                     detail.setValue(
                           column,
                           "hmac:v1:test:"
                                 + Base64.getUrlEncoder()
                                       .withoutPadding()
                                       .encodeToString(
                                             mac.doFinal(
                                                   detail.getValueString(column)
                                                         .getBytes(
                                                               StandardCharsets
                                                                     .UTF_8))));
                  }
                  catch(Exception e)
                  {
                     throw new IllegalStateException(e);
                  }
               }
               detail.setValue("message", "Changed Diagnosis");
            }
         }
      }
   }

   /*******************************************************************************
    ** Verify token hook keeps every audit and chain value free of canary.
    *******************************************************************************/
   @Test
   void tokenHookKeepsEveryAuditAndChainValueFreeOfCanary() throws Exception
   {
      var config = ChainVerificationTest.signed();
      var instance = init(config);
      instance.addTable(
            new QTableMetaData()
                  .withName("patient")
                  .withBackendName("memory")
                  .withPrimaryKeyField("id")
                  .withField(new QFieldMetaData("id", QFieldType.INTEGER))
                  .withField(
                        new QFieldMetaData("diagnosis", QFieldType.STRING)
                              .withSupplementalMetaData(new Phi())));
      instance.addSupplementalCustomizer(
            AuditActionCustomizerInterface.CUSTOMIZER_TYPE,
            new QCodeReference(TokenHook.class));
      String canary = "CANARY-PHI-" + UUID.randomUUID();
      var detail =
            new QRecord()
                  .withValue("fieldName", "diagnosis")
                  .withValue("oldValue", canary)
                  .withValue("newValue", canary)
                  .withValue("message", "Changed Diagnosis from " + canary + " to " + canary);
      new AuditAction()
            .execute(
                  new AuditInput()
                        .withAuditSingleInput(
                              new AuditSingleInput()
                                    .withAuditTableName("patient")
                                    .withAuditUserName("james")
                                    .withRecordId(17)
                                    .withTimestamp(OLD)
                                    .withMessage("Record was Edited")
                                    .withDetails(List.of(detail))));
      assertThat(STORE.all("audit")).hasSize(1);
      assertThat(STORE.all("auditDetail")).hasSize(1);
      assertThat(STORE.all("auditDetail").getFirst().getValueString("newValue"))
            .startsWith("hmac:v1:test:");
      new WormAuditChainer(config).chainOnce();
      List<String> values = new ArrayList<>();
      for(String table :
            List.of(
                  "audit",
                  "auditDetail",
                  WormAuditTables.CHAIN,
                  WormAuditTables.CHECKPOINT))
      {
         STORE.all(table)
               .forEach(
                     r ->
                           r.getValues().values().stream()
                                 .filter(Objects::nonNull)
                                 .map(Object::toString)
                                 .forEach(values::add));
      }
      for(var link : STORE.all(WormAuditTables.CHAIN))
      {
         values.add(
                  new String(
                        STORE.canonical(
                              STORE.get("audit", link.getValueLong("audit_id")),
                              AuditStore.detailIds(link)),
                        StandardCharsets.UTF_8));
      }
      for(String value : values)
      {
         assertThat(value).doesNotContain(canary);
         // Every longer substring contains a 5-character substring.
         for(int start = 0; start <= canary.length() - 5; start++)
         {
            assertThat(value).doesNotContain(canary.substring(start, start + 5));
         }
      }
      assertThat(new WormAuditVerifier(config).verify().passed()).isTrue();
   }
}
