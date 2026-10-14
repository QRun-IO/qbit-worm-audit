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

package com.kingsrook.qbits.wormaudit;


import com.kingsrook.qqq.backend.core.model.metadata.MetaDataProducerMultiOutput;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;


/*******************************************************************************
 ** Verify the scaffold's registration and configuration contract.
 *******************************************************************************/
class WormAuditQBitProducerTest
{
   /*******************************************************************************
    ** Produce the identity and exact config into an otherwise empty instance.
    *******************************************************************************/
   @Test
   void producesQBitWithoutTables()
   {
      QInstance instance = new QInstance();
      WormAuditQBitConfig config = new WormAuditQBitConfig();
      WormAuditQBitProducer producer = new WormAuditQBitProducer().withQBitConfig(config);
      MetaDataProducerMultiOutput output = producer.produce(instance);
      QBitMetaData qBit = instance.getQBits().get("com.kingsrook.qbits:qbit-worm-audit");

      assertThat(qBit).isNotNull();
      assertThat(qBit.getGroupId()).isEqualTo("com.kingsrook.qbits");
      assertThat(qBit.getArtifactId()).isEqualTo("qbit-worm-audit");
      assertThat(qBit.getVersion()).isEqualTo("0.1.0");
      assertThat(qBit.getConfig()).isSameAs(config);
      assertThat(producer.getQBitConfig()).isSameAs(config);
      assertThat(producer.isEnabled()).isTrue();
      assertThat(producer.getNamespace()).isNull();
      assertThat(output.getEach(QBitMetaData.class)).containsExactly(qBit);
      assertThat(output.getEach(QTableMetaData.class)).isEmpty();
      assertThat(instance.getTables()).isEmpty();
      assertThat(config.getRetentionYears()).isEqualTo(6);
      assertThat(config.getTableMetaDataCustomizer()).isNull();
   }



   /*******************************************************************************
    ** Configured instances may be namespaced; unconfigured scanning is disabled.
    *******************************************************************************/
   @Test
   void supportsNamespacedConfiguration()
   {
      assertThat(new WormAuditQBitProducer().isEnabled()).isFalse();
      MetaDataCustomizerInterface<QTableMetaData> customizer = (instance, table) -> table;
      WormAuditQBitConfig config = new WormAuditQBitConfig()
         .withTableMetaDataCustomizer(customizer)
         .withRetentionYears(7);
      WormAuditQBitProducer producer = new WormAuditQBitProducer()
         .withQBitConfig(config)
         .withNamespace("test");
      QInstance instance = new QInstance();
      producer.produce(instance);

      assertThat(producer.getNamespace()).isEqualTo("test");
      assertThat(instance.getQBits().get("com.kingsrook.qbits:qbit-worm-audit:test").getConfig()).isSameAs(config);
      assertThat(config.getTableMetaDataCustomizer()).isSameAs(customizer);
      assertThat(config.getRetentionYears()).isEqualTo(7);
      assertThat(instance.getTables()).isEmpty();
   }
}
