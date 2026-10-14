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


import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** v1 audit content, exactly as stored. Subsets use the same document schema for
 ** LATE_DETAIL links; no canonical content is persisted by this qbit.
 *******************************************************************************/
public final class AuditCanonical
{
   private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private AuditCanonical()
   {
   }


   /*******************************************************************************
    ** Resolve names outside this function, without looking up application data.
    *******************************************************************************/
   public static byte[] bytes(QRecord audit, String table, String user, List<QRecord> details)
   {
      Map<String, Object> header = new LinkedHashMap<>();
      header.put("clientChannel", audit.getValueString("clientChannel"));
      header.put("id", audit.getValueLong("id"));
      header.put("message", audit.getValueString("message"));
      header.put("recordId", audit.getValueString("recordId"));
      header.put("table", table);
      header.put("timestamp", TIMESTAMP.format(audit.getValueInstant("timestamp")));
      header.put("user", user);
      List<Map<String, Object>> rows = details.stream().sorted(Comparator.comparing(r -> r.getValueLong("id"))).map(detail ->
      {
         Map<String, Object> row = new LinkedHashMap<>();
         row.put("id", detail.getValueLong("id"));
         for(String field : List.of("fieldName", "message", "newValue", "oldValue"))
         {
            row.put(field, detail.getValueString(field));
         }
         return (row);
      }).toList();
      return (Jcs.bytes(Map.of("audit", header, "details", rows, "v", 1)));
   }
}
