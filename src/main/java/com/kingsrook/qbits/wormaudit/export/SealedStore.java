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


import java.io.InputStream;
import java.nio.file.Path;
import java.time.Instant;
import com.kingsrook.qbits.objectstorage.api.ListRequest;
import com.kingsrook.qbits.objectstorage.api.ObjectSummary;
import com.kingsrook.qbits.objectstorage.api.Page;
import com.kingsrook.qbits.objectstorage.api.StoredObject;


/*******************************************************************************
 ** Minimal storage boundary. The application never deletes sealed objects.
 *******************************************************************************/
public interface SealedStore
{
   /*******************************************************************************
    ** Only positively confirmed Object Lock support is acceptable.
    *******************************************************************************/
   boolean supportsLock();

   /*******************************************************************************
    ** Upload a file with COMPLIANCE retention.
    *******************************************************************************/
   String put(String key, Path file, Instant retainUntil) throws Exception;

   /*******************************************************************************
    ** Read current object metadata, or null for an absent object.
    *******************************************************************************/
   StoredObject head(String key) throws Exception;

   /*******************************************************************************
    ** Open the exact sealed version; the caller owns and closes the stream.
    *******************************************************************************/
   InputStream getVersion(String key, String versionId) throws Exception;

   /*******************************************************************************
    ** List one bounded page.
    *******************************************************************************/
   Page<ObjectSummary> list(ListRequest request) throws Exception;
}

