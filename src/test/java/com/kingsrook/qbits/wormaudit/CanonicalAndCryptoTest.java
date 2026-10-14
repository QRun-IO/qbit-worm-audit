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

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.canonical.AuditCanonical;
import com.kingsrook.qbits.wormaudit.canonical.Jcs;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qbits.wormaudit.checkpoint.Checkpoints;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/*******************************************************************************
 ** Tests and fixtures for canonical and crypto test.
 *******************************************************************************/
class CanonicalAndCryptoTest
{
   /*******************************************************************************
    ** Verify jcs ordering escaping and invalid types.
    *******************************************************************************/
   @Test
   void jcsOrderingEscapingAndInvalidTypes()
   {
      var value = new LinkedHashMap<String, Object>();
      value.put("\u20ac", "Euro");
      value.put("\ud83d\ude00", "Emoji");
      value.put("\ufb33", "Hebrew");
      value.put("a", null);
      String result = Jcs.string(value);
      assertThat(result)
            .isEqualTo(
                  "{\"a\":null,\"\u20ac\":\"Euro\",\"\ud83d\ude00\":\"Emoji\",\"\ufb33\":\"Hebrew\"}");
      assertThat(Jcs.string("\"\\\b\f\n\r\t\u0001/é"))
            .isEqualTo("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001/é\"");
      assertThat(Jcs.string(List.of(Long.MIN_VALUE, Long.MAX_VALUE)))
            .isEqualTo("[-9223372036854775808,9223372036854775807]");
      assertThatThrownBy(() -> Jcs.string(1.5)).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> Jcs.string("\ud800")).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> Jcs.string("\udc00")).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> Jcs.string("\ud800x"))
            .isInstanceOf(IllegalArgumentException.class);
   }

   /*******************************************************************************
    ** Verify exact canonical document.
    *******************************************************************************/
   @Test
   void exactCanonicalDocument()
   {
      var audit =
            new QRecord()
                  .withValue("id", 4211L)
                  .withValue("recordId", 17)
                  .withValue("message", "Record was Edited")
                  .withValue("timestamp", Instant.parse("2026-10-13T21:04:05.123456Z"));
      var detail =
            new QRecord()
                  .withValue("id", 9001L)
                  .withValue("fieldName", "title")
                  .withValue("message", "Changed Title")
                  .withValue("oldValue", "hmac:v1:test:old")
                  .withValue("newValue", "hmac:v1:test:new");
      assertThat(
                  new String(
                        AuditCanonical.bytes(audit, "cms_page", "james", List.of(detail)),
                        StandardCharsets.UTF_8))
            .isEqualTo(
                  "{\"audit\":{\"clientChannel\":null,\"id\":4211,\"message\":\"Record was"
                     + " Edited\",\"recordId\":\"17\",\"table\":\"cms_page\",\"timestamp\":\"2026-10-13T21:04:05.123456Z\",\"user\":\"james\"},\"details\":[{\"fieldName\":\"title\",\"id\":9001,\"message\":\"Changed"
                     + " Title\",\"newValue\":\"hmac:v1:test:new\",\"oldValue\":\"hmac:v1:test:old\"}],\"v\":1}");
      assertThat(
                  new String(
                        AuditCanonical.bytes(
                              audit,
                              null,
                              null,
                              List.of(
                                    new QRecord().withValue("id", 2L),
                                    new QRecord().withValue("id", 1L))),
                        StandardCharsets.UTF_8))
            .containsSubsequence("\"id\":1,", "\"id\":2,");
   }

   /*******************************************************************************
    ** Verify independent hash and merkle vectors.
    *******************************************************************************/
   @Test
   void independentHashAndMerkleVectors() throws Exception
   {
      assertThat(Hashes.link(Hashes.GENESIS, "{}".getBytes(StandardCharsets.UTF_8)))
            .isEqualTo("72f1d7c888d85ce3159bd8bbf38f3046725d3d4d6cef2b9449d9fb4b58cf7a9c");
      String a = "11".repeat(32), b = "22".repeat(32), c = "33".repeat(32);
      assertThat(Hashes.merkle(List.of(a))).isEqualTo(a);
      assertThat(Hashes.merkle(List.of(a, b, c)))
            .isEqualTo("2470b93c7954a79f41c0106caeeeae350559c2af06bd9a9ab203b163951f64f7");
      assertThatThrownBy(() -> Hashes.merkle(List.of()))
            .isInstanceOf(IllegalArgumentException.class);
   }

   /*******************************************************************************
    ** Verify checkpoint pinning and signing.
    *******************************************************************************/
   @Test
   void checkpointPinningAndSigning() throws Exception
   {
      var keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      var other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      var config =
            new WormAuditQBitConfig()
                  .withSigningKey(
                        () -> new WormAuditQBitConfig.SigningKey("a", keys.getPrivate()))
                  .withTrustedPublicKeys(Map.of("a", keys.getPublic()));
      var links =
            List.of(new QRecord().withValue("id", 1L).withValue("link_hash", "11".repeat(32)));
      var checkpoint = Checkpoints.sign(links, config, Instant.now());
      assertThat(Checkpoints.verify(checkpoint, keys.getPublic())).isTrue();
      assertThat(Checkpoints.verify(checkpoint, other.getPublic())).isFalse();
      assertThat(Checkpoints.verify(checkpoint, null)).isFalse();
      checkpoint.setValue("signature", "bad");
      assertThat(Checkpoints.verify(checkpoint, keys.getPublic())).isFalse();
      checkpoint.setValue("algorithm", "RSA");
      assertThat(Checkpoints.verify(checkpoint, keys.getPublic())).isFalse();
      config.withTrustedPublicKeys(Map.of());
      assertThatThrownBy(() -> Checkpoints.sign(links, config, Instant.now()))
            .hasMessageContaining("not pinned");
      config.withTrustedPublicKeys(Map.of("a", other.getPublic()));
      assertThatThrownBy(() -> Checkpoints.sign(links, config, Instant.now()))
            .hasMessageContaining("does not match");
   }

   /*******************************************************************************
    ** Verify ddl is reviewed rendering and rejects injection.
    *******************************************************************************/
   @Test
   void ddlIsReviewedRenderingAndRejectsInjection() throws Exception
   {
      String sql = WormAuditDdl.postgres(new WormAuditQBitConfig());
      assertThat(sql)
            .isEqualTo(
                  java.nio.file.Files.readString(
                        java.nio.file.Path.of("docs/ddl/worm-audit-postgres.sql")));
      assertThat(sql).doesNotContain("${");
      assertThat(sql).contains("GET DIAGNOSTICS stack = PG_CONTEXT", "function worm_audit_purge(timestamp with time zone)", "SET timezone = 'UTC'");
      // The documented migration contract deliberately uses physical snake_case columns.
      assertThat(sql).contains("OLD.audit_id", "OLD.timestamp", "NEW.name", "GRANT UPDATE (label, create_date, modify_date)");
      assertThat(java.nio.file.Files.readString(java.nio.file.Path.of("README.md")))
         .contains("renders table names only", "audit_detail.audit_id", "audit_user.id/name/create_date/modify_date");
      assertThat(
                  WormAuditDdl.postgres(
                        new WormAuditQBitConfig()
                              .withRetentionYears(7)
                              .withAppRole("runtime")
                              .withCoreAuditTableNames(Map.of("audit", "history.audit"))))
            .contains("\"history\".\"audit\"", "7 years", "TO \"runtime\"");
      assertThatThrownBy(() -> WormAuditDdl.identifier("a; DROP TABLE audit"))
            .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(
                  () ->
                        WormAuditDdl.postgres(
                              new WormAuditQBitConfig().withRetentionYears(0)))
            .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(
                  () -> WormAuditDdl.postgres(new WormAuditQBitConfig().withAppRole("a.b")))
            .isInstanceOf(IllegalArgumentException.class);
      var sqlError = new java.sql.SQLException("worm_audit: rejected", "P0001");
      assertThat(AppendOnlyGuard.map(new Exception(sqlError)))
            .hasMessage(AppendOnlyGuard.MESSAGE);
      assertThat(
                  AppendOnlyGuard.map(
                        new java.sql.SQLException("ERROR: worm_audit: rejected", "P0001")))
            .hasMessage(AppendOnlyGuard.MESSAGE);
      assertThat(AppendOnlyGuard.map(new java.sql.SQLException("other", "P0001")))
            .hasMessage("WORM audit operation failed");
      var original = new com.kingsrook.qqq.backend.core.exceptions.QException("original");
      assertThat(AppendOnlyGuard.map(original)).isSameAs(original);
   }
}
