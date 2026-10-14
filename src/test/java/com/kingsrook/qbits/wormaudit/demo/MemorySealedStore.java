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


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import com.kingsrook.qbits.objectstorage.api.ListRequest;
import com.kingsrook.qbits.objectstorage.api.ObjectSummary;
import com.kingsrook.qbits.objectstorage.api.Page;
import com.kingsrook.qbits.objectstorage.api.StoredObject;
import com.kingsrook.qbits.wormaudit.export.SealedStore;


/*******************************************************************************
 ** Tiny test-scope immutable store with version and COMPLIANCE retention echoes.
 *******************************************************************************/
public class MemorySealedStore implements SealedStore
{
   private final Map<String, byte[]> objects = new LinkedHashMap<>();
   private final Map<String, StoredObject> heads = new LinkedHashMap<>();

   /*******************************************************************************
    ** Demo capability.
    *******************************************************************************/
   @Override
   public boolean supportsLock()
   {
      return (true);
   }


   /*******************************************************************************
    ** Refuse overwrites and retain the exact bytes.
    *******************************************************************************/
   @Override
   public String put(String key, Path file, com.kingsrook.qbits.objectstorage.api.LockMode mode, Instant until) throws Exception
   {
      if(objects.containsKey(key))
      {
         throw (new IllegalStateException("Demo sealed object already exists"));
      }
      String version = "v" + (objects.size() + 1);
      objects.put(key, Files.readAllBytes(file));
      heads.put(key, new StoredObject().withKey(key).withVersionId(version).withLockMode(mode.name()).withLockRetainUntil(until));
      return (version);
   }


   /*******************************************************************************
    ** Exact retention metadata.
    *******************************************************************************/
   @Override
   public StoredObject head(String key)
   {
      return (heads.get(key));
   }


   /*******************************************************************************
    ** Exact version read.
    *******************************************************************************/
   @Override
   public InputStream getVersion(String key, String versionId)
   {
      if(!heads.containsKey(key) || !heads.get(key).getVersionId().equals(versionId))
      {
         throw (new IllegalArgumentException("Demo sealed version is missing"));
      }
      return (new ByteArrayInputStream(objects.get(key)));
   }


   /*******************************************************************************
    ** The small demo fits one page.
    *******************************************************************************/
   @Override
   public Page<ObjectSummary> list(ListRequest request)
   {
      return (new Page<ObjectSummary>().withItems(objects.keySet().stream().filter(k -> k.startsWith(request.getPrefix()))
         .map(k -> new ObjectSummary().withKey(k)).toList()));
   }
}
