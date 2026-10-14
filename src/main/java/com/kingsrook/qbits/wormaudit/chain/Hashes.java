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

package com.kingsrook.qbits.wormaudit.chain;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;


/*******************************************************************************
 ** SHA-256 primitives. Link predecessors are the 64 lowercase ASCII hex bytes;
 ** Merkle leaves are the decoded 32-byte link hashes, with odd nodes promoted.
 *******************************************************************************/
public final class Hashes
{
   public static final String GENESIS = "0".repeat(64);

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private Hashes()
   {
   }


   /*******************************************************************************
    ** SHA-256 digest of concatenated byte arrays.
    *******************************************************************************/
   public static byte[] digest(byte[]... parts)
   {
      try
      {
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         for(byte[] part : parts)
         {
            digest.update(part);
         }
         return (digest.digest());
      }
      catch(NoSuchAlgorithmException e)
      {
         throw (new IllegalStateException("JDK lacks SHA-256", e));
      }
   }


   /*******************************************************************************
    ** Link hash over predecessor, NUL delimiter and canonical bytes.
    *******************************************************************************/
   public static String link(String previous, byte[] canonical)
   {
      return (HexFormat.of().formatHex(digest(previous.getBytes(StandardCharsets.US_ASCII), new byte[] { 0 }, canonical)));
   }


   /*******************************************************************************
    ** Binary Merkle root; an empty range cannot be checkpointed.
    *******************************************************************************/
   public static String merkle(List<String> hashes)
   {
      if(hashes.isEmpty())
      {
         throw (new IllegalArgumentException("A Merkle range must contain links"));
      }
      List<byte[]> level = hashes.stream().map(HexFormat.of()::parseHex).toList();
      while(level.size() > 1)
      {
         List<byte[]> next = new ArrayList<>();
         for(int i = 0; i < level.size(); i += 2)
         {
            next.add(i + 1 == level.size() ? level.get(i) : digest(level.get(i), level.get(i + 1)));
         }
         level = next;
      }
      return (HexFormat.of().formatHex(level.getFirst()));
   }
}
