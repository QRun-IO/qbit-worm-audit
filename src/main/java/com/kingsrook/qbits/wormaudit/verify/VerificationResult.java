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

package com.kingsrook.qbits.wormaudit.verify;


import java.time.Instant;
import java.util.ArrayList;
import java.util.List;


/*******************************************************************************
 ** Ordered, value-free findings. Break identifiers are separately available for
 ** record navigation and alert correlation without parsing human-readable text.
 *******************************************************************************/
public class VerificationResult
{
   /*******************************************************************************
    ** One break; null ids apply to coverage and checkpoint findings.
    *******************************************************************************/
   public record Break(Long linkId, Long auditId, String reason)
   {
   }

   private final List<Break> breaks = new ArrayList<>();
   private final List<String> warnings = new ArrayList<>();
   private final Instant startedAt = Instant.now();
   private long breakCount;
   private long linksChecked;
   private Long fromLinkId;
   private Long toLinkId;

   /*******************************************************************************
    ** Add a finding in deterministic verification order.
    *******************************************************************************/
   public void add(Long linkId, Long auditId, String reason)
   {
      breakCount++;
      if(breaks.size() < 1000)
      {
         breaks.add(new Break(linkId, auditId, reason));
      }
   }


   /*******************************************************************************
    ** Count additional SQL offenders without retaining their content.
    *******************************************************************************/
   public void omitted(long count)
   {
      breakCount += count;
   }


   /*******************************************************************************
    ** Total findings, including diagnostics omitted by the bounded display limit.
    *******************************************************************************/
   public long getBreakCount()
   {
      return (breakCount);
   }


   /*******************************************************************************
    ** Keep warnings bounded even when many checkpoint ranges have been purged.
    *******************************************************************************/
   public void warn(String warning)
   {
      if(warnings.size() < 100)
      {
         warnings.add(warning);
      }
   }


   /*******************************************************************************
    ** Record the scope that was checked.
    *******************************************************************************/
   public void scope(long count, Long from, Long to)
   {
      linksChecked = count;
      fromLinkId = from;
      toLinkId = to;
   }


   /*******************************************************************************
    ** Ordered findings.
    *******************************************************************************/
   public List<Break> getBreaks()
   {
      return (List.copyOf(breaks));
   }


   /*******************************************************************************
    ** Warnings do not break the chain.
    *******************************************************************************/
   public List<String> getWarnings()
   {
      return (warnings);
   }


   /*******************************************************************************
    ** Whether all checked invariants hold.
    *******************************************************************************/
   public boolean passed()
   {
      return (breakCount == 0);
   }


   /*******************************************************************************
    ** Number of checked links.
    *******************************************************************************/
   public long getLinksChecked()
   {
      return (linksChecked);
   }


   /*******************************************************************************
    ** First checked link, null for an empty scope.
    *******************************************************************************/
   public Long getFromLinkId()
   {
      return (fromLinkId);
   }


   /*******************************************************************************
    ** Last checked link, null for an empty scope.
    *******************************************************************************/
   public Long getToLinkId()
   {
      return (toLinkId);
   }


   /*******************************************************************************
    ** Verification start time.
    *******************************************************************************/
   public Instant getStartedAt()
   {
      return (startedAt);
   }
}
