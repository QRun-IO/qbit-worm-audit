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


import java.time.Instant;
import com.kingsrook.qbits.wormaudit.WormAuditQBitConfig;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Floors move only after complete sweeps, only to ids observed before the
 ** horizon, and reset when the tables shrink below them.
 *******************************************************************************/
class SweepFloorsTest
{
   private static final Instant T0 = Instant.parse("2026-10-15T00:00:00Z");



   /*******************************************************************************
    ** Floors follow the newest observation at or before the horizon.
    *******************************************************************************/
   @Test
   void floorsAdvanceOnlyPastSettledObservationsOfCompleteSweeps()
   {
      SweepFloors floors = SweepFloors.of(new WormAuditQBitConfig());
      var first = floors.observe(T0, 10, 100);
      floors.swept(first, T0.minusSeconds(1), true, true, null);
      assertThat(floors.audit()).as("nothing observed before the horizon yet").isZero();

      var second = floors.observe(T0.plusSeconds(30), 12, 130);
      floors.swept(second, T0.plusSeconds(10), false, true, null);
      assertThat(floors.audit()).as("the header sweep hit its limit").isZero();
      assertThat(floors.detail()).isEqualTo(100);

      var third = floors.observe(T0.plusSeconds(60), 15, 160);
      floors.swept(third, T0.plusSeconds(45), true, false, null);
      assertThat(floors.audit()).isEqualTo(12);
      assertThat(floors.detail()).as("the late-detail sweep hit its limit").isEqualTo(100);

      var fourth = floors.observe(T0.plusSeconds(90), 15, 160);
      floors.swept(fourth, T0.plusSeconds(90), true, true, null);
      assertThat(floors.audit()).isEqualTo(15);
      assertThat(floors.detail()).isEqualTo(160);

      var shrunk = floors.observe(T0.plusSeconds(120), 3, 7);
      assertThat(floors.audit()).as("tables emptied below the floor: start over").isZero();
      assertThat(floors.detail()).isZero();
      floors.swept(shrunk, T0.plusSeconds(100), true, true, null);
      assertThat(floors.audit()).isZero();
   }



   /*******************************************************************************
    ** A full sweep is due first, then hourly after each complete one.
    *******************************************************************************/
   @Test
   void fullSweepIsDueFirstAndHourly()
   {
      SweepFloors floors = SweepFloors.of(new WormAuditQBitConfig());
      assertThat(floors.fullSweepDue(T0)).isTrue();
      var first = floors.observe(T0, 1, 1);
      floors.swept(first, T0, true, false, T0);
      assertThat(floors.fullSweepDue(T0.plusSeconds(30))).as("an incomplete full sweep repeats").isTrue();
      var second = floors.observe(T0.plusSeconds(30), 1, 1);
      floors.swept(second, T0, true, true, T0.plusSeconds(30));
      assertThat(floors.fullSweepDue(T0.plusSeconds(60))).isFalse();
      assertThat(floors.fullSweepDue(T0.plusSeconds(30).plus(SweepFloors.FULL_SWEEP_EVERY))).isTrue();
      assertThat(floors.fullSweepDue(T0)).as("clock moved backwards").isTrue();
   }



   /*******************************************************************************
    ** Each installed config has its own floors.
    *******************************************************************************/
   @Test
   void floorsArePerConfig()
   {
      var config = new WormAuditQBitConfig();
      assertThat(SweepFloors.of(config)).isSameAs(SweepFloors.of(config)).isNotSameAs(SweepFloors.of(new WormAuditQBitConfig()));
   }
}
