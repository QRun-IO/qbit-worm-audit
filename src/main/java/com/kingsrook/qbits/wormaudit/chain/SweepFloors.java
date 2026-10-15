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


import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.Map;
import java.util.WeakHashMap;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;


/*******************************************************************************
 ** Per-JVM id floors for the chain writer's two sweeps, so a tick reads only
 ** audit and detail rows newer than the last complete sweep instead of the whole
 ** settle window or late-detail lookback.
 **
 ** Each tick records the highest audit and audit_detail ids it can see. After a
 ** sweep that returned fewer rows than its limit, every row allocated before
 ** (settle horizon + MARGIN) ago is chained, on the same assumption the settle
 ** horizon already makes: a row whose id was allocated that long ago has
 ** committed. The floor moves to the highest id observed at or before that time.
 ** A row whose transaction commits later than that is still chained: once an
 ** hour (and after every restart) a tick ignores the floors and sweeps
 ** everything, exactly as before floors existed. Floors live in memory only; a
 ** second replica keeps its own. The daily verification checks full coverage
 ** independently of all of this.
 *******************************************************************************/
public final class SweepFloors
{
   public static final Duration MARGIN = Duration.ofMinutes(5);
   public static final Duration FULL_SWEEP_EVERY = Duration.ofHours(1);

   private static final Map<WormAuditQBitConfig, SweepFloors> BY_CONFIG = Collections.synchronizedMap(new WeakHashMap<>());

   private final Deque<Observation> observations = new ArrayDeque<>();
   private long audit;
   private long detail;
   private Instant lastFullSweep;

   /*******************************************************************************
    ** The highest ids visible at one tick.
    *******************************************************************************/
   public record Observation(Instant at, long audit, long detail)
   {
   }


   /*******************************************************************************
    ** Floors for one installed qbit (config identity), created on first use.
    *******************************************************************************/
   public static SweepFloors of(WormAuditQBitConfig config)
   {
      return (BY_CONFIG.computeIfAbsent(config, c -> new SweepFloors()));
   }


   /*******************************************************************************
    ** Audit ids at or below this are known chained.
    *******************************************************************************/
   public synchronized long audit()
   {
      return (audit);
   }


   /*******************************************************************************
    ** Detail ids at or below this are known covered (or outside the lookback).
    *******************************************************************************/
   public synchronized long detail()
   {
      return (detail);
   }


   /*******************************************************************************
    ** Whether this tick must ignore the floors: first tick, an hour since the last
    ** complete full sweep, or a clock that moved backwards.
    *******************************************************************************/
   public synchronized boolean fullSweepDue(Instant now)
   {
      return (lastFullSweep == null || now.isBefore(lastFullSweep) || !now.isBefore(lastFullSweep.plus(FULL_SWEEP_EVERY)));
   }


   /*******************************************************************************
    ** Record the highest visible ids. Ids below a floor mean rows were removed
    ** wholesale (a purge of everything, or a reset test database): start over.
    *******************************************************************************/
   public synchronized Observation observe(Instant now, long maxAudit, long maxDetail)
   {
      if(maxAudit < audit || maxDetail < detail)
      {
         observations.clear();
         audit = 0;
         detail = 0;
      }
      Observation observation = new Observation(now, maxAudit, maxDetail);
      observations.addLast(observation);
      return (observation);
   }


   /*******************************************************************************
    ** After a tick, raise each completely swept floor to the newest observation
    ** made at or before the horizon, then drop observations no longer needed. A
    ** full sweep (fullSweepAt not null) counts only when both sweeps completed.
    *******************************************************************************/
   public synchronized void swept(Observation current, Instant horizon, boolean auditsComplete, boolean detailsComplete, Instant fullSweepAt)
   {
      if(fullSweepAt != null && auditsComplete && detailsComplete)
      {
         lastFullSweep = fullSweepAt;
      }
      Observation settled = null;
      for(Observation observation : observations)
      {
         if(!observation.at().isAfter(horizon) && (settled == null || !observation.at().isBefore(settled.at())))
         {
            settled = observation;
         }
      }
      if(settled == null)
      {
         return;
      }
      if(auditsComplete)
      {
         audit = Math.max(audit, Math.min(settled.audit(), current.audit()));
      }
      if(detailsComplete)
      {
         detail = Math.max(detail, Math.min(settled.detail(), current.detail()));
      }
      Observation keep = settled;
      observations.removeIf(observation -> observation != keep && !observation.at().isAfter(horizon));
   }
}
