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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import com.fasterxml.jackson.databind.JsonNode;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.model.WormAuditHelp;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.help.QHelpContent;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Guardrail (owner requirement 2026-10-14: "all tables should be populated and
 ** the qbit should be fully using them"). For every worm_audit_* table:
 ** - runtime code (not just its model, metadata or home screen) reads or writes
 **   it;
 ** - it is either seeded by the shipped database script, or listed here with
 **   why it starts empty;
 ** - it has bundle help that says what it is for and how its rows get created
 **   (shown on the table screen and when it is empty).
 ** A new table fails this test until it is wired, seeded or explained.
 *******************************************************************************/
class WormAuditTablesGuardrailTest
{
   private static final Path MAIN = Path.of("src", "main", "java", "com", "kingsrook", "qbits", "wormaudit");

   /*******************************************************************************
    ** Tables the shipped database script (ddl/postgres/worm-audit.sql) seeds.
    *******************************************************************************/
   static final List<String> SEEDED = List.of(WormAuditTables.SETTINGS);

   /*******************************************************************************
    ** Tables that legitimately start empty, and where their rows come from.
    *******************************************************************************/
   static final Map<String, String> STARTS_EMPTY = Map.of(
      WormAuditTables.CHAIN, "log: the chain job links each settled audit record",
      WormAuditTables.CHECKPOINT, "log: the chain job signs a range every N links or minutes",
      WormAuditTables.EXPORT, "log: the daily export or Export now seals a range",
      WormAuditTables.VERIFICATION, "log: every verification run, manual or daily",
      WormAuditTables.PURGE, "log: the database owner's purge function, after retention");



   /*******************************************************************************
    ** Every table is used by runtime code.
    *******************************************************************************/
   @Test
   void everyTableIsUsedAtRuntime() throws Exception
   {
      List<String> runtimeSource;
      try(Stream<Path> files = Files.walk(MAIN))
      {
         runtimeSource = files.filter(p -> p.toString().endsWith(".java"))
            .filter(p -> !p.startsWith(MAIN.resolve("model")) && !p.startsWith(MAIN.resolve("app")) && !p.startsWith(MAIN.resolve("ddl")))
            .filter(p -> !p.endsWith("WormAuditQBitProducer.java"))
            .map(WormAuditTablesGuardrailTest::read).toList();
      }
      for(String table : WormAuditTables.ALL)
      {
         String constant = "WormAuditTables." + table.substring("worm_audit_".length()).toUpperCase();
         assertThat(runtimeSource.stream().anyMatch(source -> source.contains(constant)))
            .as(table + " (" + constant + ") must be read or written by runtime code, not only declared").isTrue();
      }
   }



   /*******************************************************************************
    ** Every table is seeded by the script or explained.
    *******************************************************************************/
   @Test
   void everyTableIsSeededOrExplained() throws Exception
   {
      String ddl = WormAuditDdl.postgres(new WormAuditQBitConfig());
      for(String table : WormAuditTables.ALL)
      {
         boolean seeded = SEEDED.contains(table);
         assertThat(seeded || STARTS_EMPTY.containsKey(table)).as(table + " must be seeded by the database script or listed in STARTS_EMPTY").isTrue();
         assertThat(seeded && STARTS_EMPTY.containsKey(table)).as(table + " cannot be both seeded and starting empty").isFalse();
         assertThat(ddl.contains("INSERT INTO public." + table + "\n") || ddl.contains("INSERT INTO public." + table + " ")).as(table + " seeded iff the script inserts it").isEqualTo(seeded);
      }
      assertThat(STARTS_EMPTY.keySet()).allMatch(WormAuditTables.ALL::contains, "STARTS_EMPTY names only real tables");
   }



   /*******************************************************************************
    ** Every table and the app have bundle help that says how rows get created.
    *******************************************************************************/
   @Test
   void everyTableHasEmptyStateHelp() throws Exception
   {
      QInstance instance = WormAuditTestSupport.init(new WormAuditQBitConfig());
      assertThat(WormAuditHelp.entries()).allSatisfy((key, entry) -> assertThat(entry.path("summary").asText().length()).as(key).isLessThanOrEqualTo(120));
      for(String table : WormAuditTables.ALL)
      {
         List<QHelpContent> help = instance.getTable(table).getHelpContent() == null ? null : instance.getTable(table).getHelpContent().get(WormAuditHelp.SLOT);
         assertThat(help).as(table + " table help").isNotEmpty();
         assertThat(help.get(0).getContent()).as(table + " help says how rows get created").contains("How rows get created");
      }
      assertThat(instance.getApp("worm_audit").getHelpContent()).containsKey(WormAuditHelp.SLOT);
      for(Map.Entry<String, JsonNode> entry : WormAuditHelp.entries().entrySet())
      {
         String key = entry.getKey();
         assertThat(key.startsWith("app:") || WormAuditTables.ALL.contains(key.substring(6, key.indexOf(';')))).as("help names only real tables: " + key).isTrue();
      }
   }



   /*******************************************************************************
    ** A host's own help is never replaced.
    *******************************************************************************/
   @Test
   void hostHelpIsKept() throws Exception
   {
      QInstance instance = WormAuditTestSupport.init(new WormAuditQBitConfig());
      instance.getTable(WormAuditTables.CHAIN).getHelpContent().put(WormAuditHelp.SLOT, List.of(new QHelpContent().withContentAsMarkdown("host text")));
      WormAuditHelp.apply(instance, new WormAuditQBitConfig());
      assertThat(instance.getTable(WormAuditTables.CHAIN).getHelpContent().get(WormAuditHelp.SLOT)).hasSize(1);
      assertThat(instance.getTable(WormAuditTables.CHAIN).getHelpContent().get(WormAuditHelp.SLOT).get(0).getContent()).isEqualTo("host text");
   }



   /*******************************************************************************
    **
    *******************************************************************************/
   private static String read(Path path)
   {
      try
      {
         return (Files.readString(path, StandardCharsets.UTF_8));
      }
      catch(Exception e)
      {
         throw (new IllegalStateException(e));
      }
   }

}
