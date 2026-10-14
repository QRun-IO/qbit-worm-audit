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

package com.kingsrook.qbits.wormaudit.checkpoint;


import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import com.kingsrook.qbits.wormaudit.canonical.Jcs;
import com.kingsrook.qbits.wormaudit.chain.Hashes;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Ed25519 checkpoint envelopes. Trust comes exclusively from host-pinned keys,
 ** never the public_key supplied by an untrusted checkpoint row.
 *******************************************************************************/
public final class Checkpoints
{
   private static final List<String> SIGNED_FIELDS = List.of("from_link_id", "to_link_id", "link_count", "head_hash", "merkle_root", "algorithm", "key_id");

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private Checkpoints()
   {
   }


   /*******************************************************************************
    ** The exact signed payload; public_key and signature are envelope fields.
    *******************************************************************************/
   public static byte[] payload(QRecord checkpoint)
   {
      Map<String, Object> fields = new LinkedHashMap<>();
      for(String field : SIGNED_FIELDS)
      {
         fields.put(field, field.endsWith("_id") && !field.equals("key_id") || field.equals("link_count")
            ? checkpoint.getValueLong(field) : checkpoint.getValueString(field));
      }
      return (Jcs.bytes(fields));
   }


   /*******************************************************************************
    ** Create a checkpoint only when the configured private key matches its pin.
    *******************************************************************************/
   public static QRecord sign(List<QRecord> links, WormAuditQBitConfig config, Instant now) throws GeneralSecurityException
   {
      WormAuditQBitConfig.SigningKey key = config.getSigningKey().get();
      PublicKey publicKey = config.getTrustedPublicKeys().get(key.keyId());
      if(publicKey == null)
      {
         throw (new GeneralSecurityException("Signing key id is not pinned"));
      }
      QRecord record = new QRecord().withValue("from_link_id", links.getFirst().getValueLong("id"))
         .withValue("to_link_id", links.getLast().getValueLong("id")).withValue("link_count", (long) links.size())
         .withValue("head_hash", links.getLast().getValueString("link_hash"))
         .withValue("merkle_root", Hashes.merkle(links.stream().map(r -> r.getValueString("link_hash")).toList()))
         .withValue("algorithm", "Ed25519").withValue("key_id", key.keyId())
         .withValue("public_key", Base64.getEncoder().encodeToString(publicKey.getEncoded())).withValue("created_at", now);
      Signature signature = Signature.getInstance("Ed25519");
      signature.initSign(key.privateKey());
      signature.update(payload(record));
      record.setValue("signature", Base64.getEncoder().encodeToString(signature.sign()));
      if(!verify(record, publicKey))
      {
         throw (new GeneralSecurityException("Signing private key does not match its pin"));
      }
      return (record);
   }


   /*******************************************************************************
    ** Verify with a pinned key, rejecting substituted algorithms and public keys.
    *******************************************************************************/
   public static boolean verify(QRecord record, PublicKey pin)
   {
      try
      {
         if(pin == null || !"Ed25519".equals(record.getValueString("algorithm"))
            || !Base64.getEncoder().encodeToString(pin.getEncoded()).equals(record.getValueString("public_key")))
         {
            return (false);
         }
         Signature signature = Signature.getInstance("Ed25519");
         signature.initVerify(pin);
         signature.update(payload(record));
         return (signature.verify(Base64.getDecoder().decode(record.getValueString("signature"))));
      }
      catch(GeneralSecurityException | IllegalArgumentException e)
      {
         return (false);
      }
   }
}
