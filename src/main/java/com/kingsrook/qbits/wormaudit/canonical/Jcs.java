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

package com.kingsrook.qbits.wormaudit.canonical;


import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;


/*******************************************************************************
 ** RFC 8785 serialization of the audit schema: strings, integer longs, null,
 ** objects and arrays. Java String ordering is UTF-16 code-unit ordering. Reject
 ** malformed surrogate pairs instead of silently replacing them during UTF-8 encoding.
 *******************************************************************************/
public final class Jcs
{
   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private Jcs()
   {
   }


   /*******************************************************************************
    ** Encode a document with no insignificant whitespace.
    *******************************************************************************/
   public static byte[] bytes(Object value)
   {
      return (string(value).getBytes(StandardCharsets.UTF_8));
   }


   /*******************************************************************************
    ** Serialize only the value types supported by the v1 schema.
    *******************************************************************************/
   public static String string(Object value)
   {
      if(value == null)
      {
         return ("null");
      }
      if(value instanceof String text)
      {
         return (quote(text));
      }
      if(value instanceof Long || value instanceof Integer)
      {
         return (value.toString());
      }
      if(value instanceof List<?> list)
      {
         return ("[" + String.join(",", list.stream().map(Jcs::string).toList()) + "]");
      }
      if(value instanceof Map<?, ?> map)
      {
         TreeMap<String, Object> sorted = new TreeMap<>();
         map.forEach((key, item) -> sorted.put((String) key, item));
         return ("{" + String.join(",", sorted.entrySet().stream().map(e -> quote(e.getKey()) + ":" + string(e.getValue())).toList()) + "}");
      }
      throw (new IllegalArgumentException("Unsupported canonical value type"));
   }


   /*******************************************************************************
    ** JSON escaping mandated by JCS, including lowercase control escapes.
    *******************************************************************************/
   private static String quote(String text)
   {
      StringBuilder out = new StringBuilder("\"");
      for(int i = 0; i < text.length(); i++)
      {
         char c = text.charAt(i);
         switch(c)
         {
            case '"' -> out.append("\\\"");
            case '\\' -> out.append("\\\\");
            case '\b' -> out.append("\\b");
            case '\f' -> out.append("\\f");
            case '\n' -> out.append("\\n");
            case '\r' -> out.append("\\r");
            case '\t' -> out.append("\\t");
            default ->
            {
               if(c < 32)
               {
                  out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
               }
               else if(Character.isHighSurrogate(c))
               {
                  if(i + 1 >= text.length() || !Character.isLowSurrogate(text.charAt(i + 1)))
                  {
                     throw (new IllegalArgumentException("Unpaired surrogate in canonical string"));
                  }
                  out.append(c).append(text.charAt(++i));
               }
               else if(Character.isLowSurrogate(c))
               {
                  throw (new IllegalArgumentException("Unpaired surrogate in canonical string"));
               }
               else
               {
                  out.append(c);
               }
            }
         }
      }
      return (out.append('"').toString());
   }
}
