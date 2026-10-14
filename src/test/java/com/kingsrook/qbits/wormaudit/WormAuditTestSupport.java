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

import com.kingsrook.qbits.wormaudit.chain.AuditStore;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.model.actions.tables.delete.DeleteInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.update.UpdateInput;
import com.kingsrook.qqq.backend.core.model.audits.AuditsMetaDataProvider;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.core.model.metadata.QBackendMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldMetaData;
import com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryBackendModule;
import com.kingsrook.qqq.backend.core.modules.backend.implementations.memory.MemoryRecordStore;

import java.time.Instant;
import java.util.List;

public class WormAuditTestSupport {
    static final Instant OLD = Instant.parse("2020-01-02T03:04:05.123456Z");
    static final AuditStore STORE = new AuditStore(null);

    static QInstance init(WormAuditQBitConfig config) throws Exception {
        MemoryRecordStore.fullReset();
        QInstance instance =
                core(
                        new QBackendMetaData()
                                .withName("memory")
                                .withBackendType(MemoryBackendModule.class));
        new WormAuditQBitProducer()
                .withQBitConfig(config.withBackendName("memory"))
                .produce(instance);
        QContext.init(instance, new QSession());
        lookups();
        return (instance);
    }

    static QInstance core(QBackendMetaData backend) throws Exception {
        QInstance instance = new QInstance();
        instance.withInstanceDefaultAuthentication(
                new com.kingsrook.qqq.backend.core.model.metadata.authentication
                                .QAuthenticationMetaData()
                        .withType(
                                com.kingsrook.qqq.backend.core.model.metadata.QAuthenticationType
                                        .FULLY_ANONYMOUS)
                        .withName("anon"));
        instance.addBackend(backend);
        new AuditsMetaDataProvider().defineAll(instance, backend.getName(), null);
        instance.getTable("audit")
                .withField(new QFieldMetaData("clientChannel", QFieldType.STRING));
        return (instance);
    }

    static void lookups() throws Exception {
        STORE.insert(
                "auditTable",
                List.of(
                        new QRecord()
                                .withValue("id", 1)
                                .withValue("name", "cms_page")
                                .withValue("label", "Page")));
        STORE.insert(
                "auditUser", List.of(new QRecord().withValue("id", 1).withValue("name", "james")));
    }

    static QRecord audit(long id) throws Exception {
        QRecord row =
                new QRecord()
                        .withValue("id", id)
                        .withValue("auditTableId", 1)
                        .withValue("auditUserId", 1)
                        .withValue("recordId", 17)
                        .withValue("message", "Record was Edited")
                        .withValue("timestamp", OLD.plusSeconds(id));
        return (STORE.insert("audit", List.of(row)).getFirst());
    }

    static QRecord detail(long id, long auditId) throws Exception {
        return (STORE.insert(
                        "auditDetail",
                        List.of(
                                new QRecord()
                                        .withValue("id", id)
                                        .withValue("auditId", auditId)
                                        .withValue("fieldName", "title")
                                        .withValue("message", "Changed Title")
                                        .withValue("oldValue", "old")
                                        .withValue("newValue", "new")))
                .getFirst());
    }

    static void tamper(String table, long id, String field, java.io.Serializable value)
            throws Exception {
        MemoryRecordStore.getInstance()
                .update(
                        new UpdateInput(table)
                                .withRecords(
                                        List.of(
                                                new QRecord()
                                                        .withValue(
                                                                "id",
                                                                table.equals("auditTable")
                                                                                || table.equals(
                                                                                        "auditUser")
                                                                        ? (java.io.Serializable)
                                                                                (int) id
                                                                        : id)
                                                        .withValue(field, value))),
                        false);
    }

    /** What the shipped database script does for the singleton: insert row 1 from the host config, only when absent. */
    public static void seedSettings(WormAuditQBitConfig config) throws Exception {
        if (STORE.get(com.kingsrook.qbits.wormaudit.model.WormAuditTables.SETTINGS, 1) == null) {
            STORE.insert(
                    com.kingsrook.qbits.wormaudit.model.WormAuditTables.SETTINGS,
                    List.of(WormAuditSettings.defaults(config)));
        }
        config.invalidateSettings();
    }

    static void remove(String table, long id) throws Exception {
        MemoryRecordStore.getInstance().delete(new DeleteInput(table).withPrimaryKeys(List.of(id)));
    }
}
