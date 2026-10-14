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

package com.kingsrook.qbits.wormaudit.export;


import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kingsrook.qbits.objectstorage.api.StoredObject;
import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Version-one export encoding and temporary files. JSON errors never echo input.
 *******************************************************************************/
public class ExportFiles implements AutoCloseable
{
   public static final List<String> NAMES = List.of("links.jsonl", "checkpoints.jsonl", "manifest.json");
   private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
      .enable(DeserializationFeature.USE_LONG_FOR_INTS).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
   private final Path directory;

   /*******************************************************************************
    ** Create a private temporary directory, removed on all normal failure paths.
    *******************************************************************************/
   public ExportFiles() throws IOException
   {
      directory = Files.createTempDirectory("worm-audit-");
   }


   /*******************************************************************************
    ** Resolve only one of the fixed filenames, never a manifest-supplied path.
    *******************************************************************************/
   public Path file(String name)
   {
      if(!NAMES.contains(name))
      {
         throw (new IllegalArgumentException("Unknown export file"));
      }
      return (directory.resolve(name));
   }


   /*******************************************************************************
    ** Parse the JCS schema with strict duplicate and trailing-token rejection.
    *******************************************************************************/
   public static Map<String, Object> parse(byte[] bytes) throws IOException
   {
      try
      {
         return (JSON.readValue(bytes, new TypeReference<Map<String, Object>>() {}));
      }
      catch(Exception e)
      {
         throw (new IOException("Invalid sealed JSON"));
      }
   }


   /*******************************************************************************
    ** Wire representation of a chain row, excluding database-only timestamps.
    *******************************************************************************/
   public static Map<String, Object> link(QRecord row)
   {
      return (Map.of("id", row.getValueLong("id"), "kind", row.getValueString("kind"),
         "auditId", row.getValueLong("audit_id"), "detailIds", AuditStore.detailIds(row),
         "prevHash", row.getValueString("prev_hash"), "linkHash", row.getValueString("link_hash")));
   }


   /*******************************************************************************
    ** Preserve every checkpoint field, representing the timestamp as UTC text.
    *******************************************************************************/
   public static Map<String, Object> checkpoint(QRecord row)
   {
      Map<String, Object> fields = new LinkedHashMap<>();
      for(String key : List.of("id", "from_link_id", "to_link_id", "link_count"))
      {
         fields.put(key, row.getValueLong(key));
      }
      for(String key : List.of("head_hash", "merkle_root", "algorithm", "key_id", "public_key", "signature"))
      {
         fields.put(key, row.getValueString(key));
      }
      fields.put("created_at", row.getValueInstant("created_at").toString());
      return (fields);
   }


   /*******************************************************************************
    ** Convert a checkpoint envelope back to the phase (a) signature input.
    *******************************************************************************/
   public static QRecord record(Map<String, Object> fields)
   {
      QRecord row = new QRecord();
      fields.forEach((key, value) -> row.setValue(key, (Serializable) value));
      return (row);
   }


   /*******************************************************************************
    ** Compute a digest without materializing a file.
    *******************************************************************************/
   public static String sha256(Path path) throws Exception
   {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try(InputStream input = Files.newInputStream(path))
      {
         byte[] buffer = new byte[65536];
         int read;
         while((read = input.read(buffer)) != -1)
         {
            digest.update(buffer, 0, read);
         }
      }
      return (HexFormat.of().formatHex(digest.digest()));
   }


   /*******************************************************************************
    ** A lock echo is required even if a provider advertises the capability.
    *******************************************************************************/
   public static boolean locked(StoredObject object, String mode, java.time.Instant until)
   {
      return (object != null && java.util.Objects.equals(mode, object.getLockMode()) && object.getLockRetainUntil() != null
         && !object.getLockRetainUntil().isBefore(until));
   }


   /*******************************************************************************
    ** A null version belongs to unversioned storage and cannot be sealed.
    *******************************************************************************/
   public static boolean validVersion(String versionId)
   {
      return (versionId != null && !versionId.isBlank() && !"null".equals(versionId));
   }


   /*******************************************************************************
    ** Fetch covered detail rows in bounded IN batches.
    *******************************************************************************/
   public static Map<Long, QRecord> details(AuditStore store, List<QRecord> links) throws Exception
   {
      List<Long> ids = new ArrayList<>();
      for(QRecord link : links)
      {
         List<Long> covered = AuditStore.detailIds(link);
         if(covered.size() > 250)
         {
            throw (new IOException("Invalid detail coverage"));
         }
         ids.addAll(covered);
      }
      Map<Long, QRecord> rows = new LinkedHashMap<>();
      for(int start = 0; start < ids.size(); start += 1000)
      {
         rows.putAll(AuditStore.index(store.in("auditDetail", "id", ids.subList(start, Math.min(start + 1000, ids.size())))));
      }
      return (rows);
   }


   /*******************************************************************************
    ** Remove only the three owned files and their directory.
    *******************************************************************************/
   @Override
   public void close() throws IOException
   {
      IOException failure = null;
      for(String name : NAMES)
      {
         try
         {
            Files.deleteIfExists(file(name));
         }
         catch(IOException e)
         {
            failure = new IOException("Cannot remove temporary export files");
         }
      }
      Files.deleteIfExists(directory);
      if(failure != null)
      {
         throw (failure);
      }
   }
}

