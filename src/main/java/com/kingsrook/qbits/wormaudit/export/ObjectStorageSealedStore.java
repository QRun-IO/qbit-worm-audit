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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import com.kingsrook.qbits.objectstorage.api.Capability;
import com.kingsrook.qbits.objectstorage.api.CapabilityStatus;
import com.kingsrook.qbits.objectstorage.api.ListRequest;
import com.kingsrook.qbits.objectstorage.api.ObjectStorage;
import com.kingsrook.qbits.objectstorage.api.ObjectSummary;
import com.kingsrook.qbits.objectstorage.api.Page;
import com.kingsrook.qbits.objectstorage.api.PutRequest;
import com.kingsrook.qbits.objectstorage.api.StorageBucket;
import com.kingsrook.qbits.objectstorage.api.StorageKeys;
import com.kingsrook.qbits.objectstorage.api.StoredObject;
import com.kingsrook.qbits.objectstorage.config.BucketRole;
import com.kingsrook.qbits.objectstorage.internal.ObjectStorageRuntime;
import com.kingsrook.qbits.objectstorage.internal.SecretRefs;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;


/*******************************************************************************
 ** Thin system-caller adapter to qbit-object-storage.
 *******************************************************************************/
public class ObjectStorageSealedStore implements SealedStore
{
   private final StorageBucket bucket;

   /*******************************************************************************
    ** Bind the recorded alias, so old exports survive configuration changes.
    *******************************************************************************/
   public ObjectStorageSealedStore(String alias, String runId)
   {
      bucket = ObjectStorage.asSystem("worm_audit", runId).bucket(alias);
   }


   /*******************************************************************************
    ** Refuse unknown, partial, or unsupported lock capabilities.
    *******************************************************************************/
   @Override
   public boolean supportsLock()
   {
      return (bucket.config().getRole() == BucketRole.BACKUP
         && bucket.capability(Capability.OBJECT_LOCK) == CapabilityStatus.SUPPORTED);
   }


   /*******************************************************************************
    ** Report the provider capability without collapsing UNKNOWN into UNSUPPORTED.
    *******************************************************************************/
   @Override
   public CapabilityStatus lockCapability()
   {
      return (bucket.capability(Capability.OBJECT_LOCK));
   }


   /*******************************************************************************
    ** Stream a bounded upload and close the source even when the provider fails.
    *******************************************************************************/
   @Override
   public String put(String key, Path file, com.kingsrook.qbits.objectstorage.api.LockMode mode, Instant retainUntil) throws Exception
   {
      try(InputStream input = Files.newInputStream(file))
      {
         return (bucket.put(PutRequest.of(key, input).withContentLength(Files.size(file))
            .withObjectLock(mode, retainUntil)).getVersionId());
      }
   }


   /*******************************************************************************
    ** Read retention metadata.
    *******************************************************************************/
   @Override
   public StoredObject head(String key)
   {
      return (bucket.head(key).orElse(null));
   }


   /*******************************************************************************
    ** RC.2 has no version GET facade. Reuse its configured system connection,
    ** key normalization and limiter; closing the stream closes the S3 response.
    *******************************************************************************/
   @Override
   public InputStream getVersion(String key, String versionId) throws IOException
   {
      if(!ExportFiles.validVersion(versionId))
      {
         throw (new IOException("Missing sealed object version"));
      }
      var connection = ObjectStorageRuntime.connection(bucket.config().getConnection());
      try(var ignored = connection.getRateLimiter().acquire())
      {
         var input = connection.client().getObject(GetObjectRequest.builder()
            .bucket(SecretRefs.resolveSetting(bucket.config().getBucketName())).key(StorageKeys.normalize(key)).versionId(versionId).build());
         if(!versionId.equals(input.response().versionId()))
         {
            input.close();
            throw (new IOException("Storage returned a different object version"));
         }
         return (input);
      }
   }


   /*******************************************************************************
    ** Forward bounded listing.
    *******************************************************************************/
   @Override
   public Page<ObjectSummary> list(ListRequest request)
   {
      return (bucket.list(request));
   }
}

