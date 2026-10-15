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

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.metadata.code.QCodeReference;
import com.kingsrook.qqq.backend.module.rdbms.jdbc.SimpleConnectionProvider;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;
import com.kingsrook.qqq.backend.module.rdbms.strategy.BaseRDBMSActionStrategy;

/*******************************************************************************
 ** Tests and fixtures for rdbms test support.
 *******************************************************************************/
class RdbmsTestSupport
{
   // RC.5 supplies the RDBMS actions and a pluggable strategy. Hosts supply their
   // PostgreSQL quoting strategy; this fixture uses the core actions unchanged.
   /*******************************************************************************
    ** Tests and fixtures for postgres strategy.
    *******************************************************************************/
   public static class PostgresStrategy extends BaseRDBMSActionStrategy
   {
      /*******************************************************************************
       ** Verify get identifier quote string.
       *******************************************************************************/
      @Override
      public String getIdentifierQuoteString()
      {
         return ("\"");
      }

      /*******************************************************************************
       ** Verify get insert default values clause.
       *******************************************************************************/
      @Override
      public String getInsertDefaultValuesClause()
      {
         return ("DEFAULT VALUES");
      }
   }

   /*******************************************************************************
    ** Verify instance.
    *******************************************************************************/
   static QInstance instance(
         String url, String user, String password, WormAuditQBitConfig config, boolean postgres)
         throws Exception
   {
      com.kingsrook.qqq.backend.module.rdbms.jdbc.ConnectionManager.resetConnectionProviders();
      var backend =
            new RDBMSBackendMetaData()
                  .withName("db")
                  .withVendor(postgres ? "postgresql" : "h2")
                  .withJdbcUrl(url)
                  .withJdbcDriverClassName(
                        postgres ? "org.postgresql.Driver" : "org.h2.Driver")
                  .withUsername(user)
                  .withPassword(password)
                  .withConnectionProvider(new QCodeReference(SimpleConnectionProvider.class));
      if(postgres)
      {
         backend.withActionStrategyCodeReference(new QCodeReference(PostgresStrategy.class));
      }
      QInstance instance = WormAuditTestSupport.core(backend);
      for(var table : instance.getTables().values())
      {
         table.withBackendDetails(
               new RDBMSTableBackendDetails().withTableName(snake(table.getName())));
         table.getFields().values().forEach(f -> f.withBackendName(snake(f.getName())));
      }
      new WormAuditQBitProducer().withQBitConfig(config.withBackendName("db")).produce(instance);
      return (instance);
   }

   /*******************************************************************************
    ** Verify snake.
    *******************************************************************************/
   static String snake(String value)
   {
      return (value.replaceAll("([a-z])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT));
   }

   /*******************************************************************************
    ** Verify create tables.
    *******************************************************************************/
   static void createTables(Connection connection, QInstance instance, boolean coreOnly)
         throws Exception
   {
      for(var table : instance.getTables().values())
      {
         if(coreOnly && table.getName().startsWith("worm_audit_"))
         {
            continue;
         }
         List<String> columns = new ArrayList<>();
         for(var field : table.getFields().values())
         {
            String type =
                  switch(field.getType())
                  {
                     case INTEGER -> "integer";
                     case LONG -> "bigint";
                     case DATE_TIME -> "timestamp(6) with time zone";
                     default -> "text";
                  };
            if(field.getName().equals(table.getPrimaryKeyField()))
            {
               type +=
                        table.getName().equals("worm_audit_chain") || table.getName().equals("worm_audit_chain_detail")
                              ? " PRIMARY KEY"
                              : " GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY";
            }
            columns.add(
                  WormAuditDdl.identifier(
                              field.getBackendName() == null
                                    ? field.getName()
                                    : field.getBackendName())
                        + " "
                        + type);
         }
         String name = ((RDBMSTableBackendDetails) table.getBackendDetails()).getTableName();
         try(var statement = connection.createStatement())
         {
            statement.execute(
                  "CREATE TABLE "
                        + WormAuditDdl.identifier(name)
                        + " ("
                        + String.join(",", columns)
                        + ")");
         }
      }
   }
}
