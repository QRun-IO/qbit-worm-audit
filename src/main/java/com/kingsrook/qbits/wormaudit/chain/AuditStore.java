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


import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import com.kingsrook.qbits.wormaudit.canonical.AuditCanonical;
import com.kingsrook.qbits.wormaudit.ddl.WormAuditDdl;
import com.kingsrook.qbits.wormaudit.guard.AppendOnlyGuard;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qbits.wormaudit.verify.VerificationResult;
import com.kingsrook.qqq.backend.core.actions.QBackendTransaction;
import com.kingsrook.qqq.backend.core.actions.tables.CountAction;
import com.kingsrook.qqq.backend.core.actions.tables.InsertAction;
import com.kingsrook.qqq.backend.core.actions.tables.QueryAction;
import com.kingsrook.qqq.backend.core.context.QContext;
import com.kingsrook.qqq.backend.core.exceptions.QException;
import com.kingsrook.qqq.backend.core.model.actions.tables.count.CountInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.insert.InsertInput;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QCriteriaOperator;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterCriteria;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QFilterOrderBy;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QQueryFilter;
import com.kingsrook.qqq.backend.core.model.actions.tables.query.QueryInput;
import com.kingsrook.qqq.backend.core.model.data.QRecord;
import com.kingsrook.qqq.backend.module.rdbms.actions.RDBMSTransaction;
import com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSTableBackendDetails;


/*******************************************************************************
 ** QQQ storage shared by chainer, verifier and future export code. All reads use
 ** the caller's transaction; only insert operations exist here. Bypass applies
 ** to internal catalog work after process permission checks, never user requests.
 *******************************************************************************/
public class AuditStore
{
   /*******************************************************************************
    ** Every (detail id, link id) pair the chain's own detail lists cover.
    *******************************************************************************/
   private static final String CHAIN_PAIRS = "SELECT x.id::bigint AS detail_id, c.id AS chain_id FROM worm_audit_chain c"
      + " CROSS JOIN LATERAL unnest(string_to_array(c.detail_ids, ',')) AS x(id) WHERE c.detail_ids <> ''";

   /*******************************************************************************
    ** Chain coverage counted per detail id, aggregated in one pass.
    *******************************************************************************/
   private static final String CHAIN_COVERAGE = "SELECT detail_id AS id, count(*) AS n FROM (" + CHAIN_PAIRS + ") pairs GROUP BY detail_id";

   private final QBackendTransaction transaction;
   private final Map<String, String> names = new LinkedHashMap<>(16, 0.75F, true);
   private Boolean timestampWithZone;
   private Boolean postgres;


   /*******************************************************************************
    ** Bind operations to one snapshot/transaction, or the memory backend.
    *******************************************************************************/
   public AuditStore(QBackendTransaction transaction)
   {
      this.transaction = transaction;
   }


   /*******************************************************************************
    ** Read in deterministic id order, explicitly fetching TEXT fields.
    *******************************************************************************/
   public List<QRecord> query(String table, QQueryFilter filter) throws QException
   {
      QueryInput input = new QueryInput(table).withFilter(filter).withTransaction(transaction).withShouldFetchHeavyFields(true);
      input.withPermissionBypass("WORM audit internal read");
      return (new QueryAction().execute(input).getRecords());
   }


   /*******************************************************************************
    ** Project only summary fields; home reads never fetch audit content.
    *******************************************************************************/
   public List<QRecord> summary(String table, QQueryFilter filter, Set<String> fields) throws QException
   {
      QueryInput input = new QueryInput(table).withFilter(filter).withTransaction(transaction)
         .withFieldNamesToInclude(fields).withShouldFetchHeavyFields(true);
      input.withPermissionBypass("WORM audit home summary after widget permission check");
      return (new QueryAction().execute(input).getRecords());
   }


   /*******************************************************************************
    ** Aggregate counts avoid loading the live chain for the home.
    *******************************************************************************/
   public long count(String table, QQueryFilter filter) throws QException
   {
      CountInput input = new CountInput(table).withFilter(filter).withTransaction(transaction);
      input.withPermissionBypass("WORM audit home count after widget permission check");
      return (new CountAction().execute(input).getCount());
   }


   /*******************************************************************************
    ** Count the same AUDIT anti-join as the writer, split at the settle horizon.
    *******************************************************************************/
   public long unchainedCount(Instant cutoff, boolean settled) throws QException
   {
      if(isRdbms())
      {
         String sql = "SELECT count(*) FROM " + physical("audit") + " a WHERE a." + column("audit", "timestamp")
            + (settled ? " < ?" : " >= ?") + unchainedPredicate();
         return (sqlIds(sql, cutoff).getFirst());
      }
      Set<Long> covered = summary(WormAuditTables.CHAIN, new QQueryFilter(new QFilterCriteria("kind", QCriteriaOperator.EQUALS, "AUDIT")), Set.of("audit_id"))
         .stream().map(r -> r.getValueLong("audit_id")).collect(Collectors.toSet());
      return (summary("audit", new QQueryFilter(), Set.of("id", "timestamp")).stream()
         .filter(r -> r.getValueInstant("timestamp") != null && r.getValueInstant("timestamp").isBefore(cutoff) == settled
            && !covered.contains(r.getValueLong("id"))).count());
   }


   /*******************************************************************************
    ** Shared SQL coverage predicate for both writer selection and home counts.
    *******************************************************************************/
   private String unchainedPredicate()
   {
      return (" AND NOT EXISTS (SELECT 1 FROM worm_audit_chain c WHERE c.audit_id=a." + column("audit", "id") + " AND c.kind='AUDIT')");
   }


   /*******************************************************************************
    ** All records ordered by id.
    *******************************************************************************/
   public List<QRecord> all(String table) throws QException
   {
      return (query(table, new QQueryFilter().withOrderBy(new QFilterOrderBy("id", true))));
   }


   /*******************************************************************************
    ** An equality query.
    *******************************************************************************/
   public List<QRecord> where(String table, String field, Serializable value) throws QException
   {
      // Core lookup keys are INTEGER while audit and chain keys are LONG.
      // Memory equality is type-sensitive; normalize to the declared field type.
      if(value instanceof Number number && QContext.getQInstance().getTable(table).getField(field).getType()
         == com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.INTEGER)
      {
         value = Math.toIntExact(number.longValue());
      }
      return (query(table, new QQueryFilter(new QFilterCriteria(field, QCriteriaOperator.EQUALS, value)).withOrderBy(new QFilterOrderBy("id", true))));
   }


   /*******************************************************************************
    ** Return a row or null if a tamper removed it.
    *******************************************************************************/
   public QRecord get(String table, long id) throws QException
   {
      return (where(table, "id", id).stream().findFirst().orElse(null));
   }


   /*******************************************************************************
    ** Insert a batch, propagating failures so a transaction can roll back.
    *******************************************************************************/
   public List<QRecord> insert(String table, List<QRecord> rows) throws QException
   {
      if(rows.isEmpty())
      {
         return (rows);
      }
      try
      {
         if(WormAuditTables.ALL.contains(table) && QContext.getQInstance().getBackendForTable(table)
            instanceof com.kingsrook.qqq.backend.module.rdbms.model.metadata.RDBMSBackendMetaData)
         {
            // RC.5 binds Instant as a UTC LocalDateTime, which shifts timestamptz
            // in non-UTC sessions. Its Timestamp path preserves the actual instant.
            rows.forEach(row -> row.getValues().replaceAll((field, value) -> value instanceof Instant instant ? Timestamp.from(instant) : value));
         }
         InsertInput input = new InsertInput(table).withRecords(rows).withTransaction(transaction).withOmitDmlAudit(true);
         input.withPermissionBypass("WORM audit internal append");
         List<QRecord> inserted = new InsertAction().execute(input).getRecords();
         for(QRecord row : inserted)
         {
            if(row.getErrors() != null && !row.getErrors().isEmpty())
            {
               // Never echo a rejected record value into logs or alerts.
               throw (new QException("WORM audit append failed for " + table));
            }
         }
         return (inserted);
      }
      catch(Exception e)
      {
         throw (AppendOnlyGuard.map(e));
      }
   }


   /*******************************************************************************
    ** Parse explicit coverage; duplicates are retained so verification sees them.
    *******************************************************************************/
   public static List<Long> detailIds(QRecord link)
   {
      String ids = link.getValueString("detail_ids");
      return (ids == null || ids.isEmpty() ? List.of() : java.util.Arrays.stream(ids.split(",")).map(Long::valueOf).toList());
   }


   /*******************************************************************************
    ** Resolve a lookup name without touching application tables.
    *******************************************************************************/
   public String name(String table, Long id) throws QException
   {
      if(id == null)
      {
         return (null);
      }
      String key = table + ":" + id;
      if(names.containsKey(key))
      {
         return (names.get(key));
      }
      QRecord row = get(table, id);
      if(row == null)
      {
         throw (new QException("Missing " + table + " " + id));
      }
      if(names.size() >= 2000)
      {
         names.remove(names.keySet().iterator().next());
      }
      names.put(key, row.getValueString("name"));
      return (row.getValueString("name"));
   }


   /*******************************************************************************
    ** Canonical bytes for the exact detail ids recorded on a link.
    *******************************************************************************/
   public byte[] canonical(QRecord audit, List<Long> ids) throws QException
   {
      return (canonical(audit, ids, index(in("auditDetail", "id", ids))));
   }


   /*******************************************************************************
    ** Settled unchained headers. RDBMS uses an anti-join under the writer lock;
    ** memory uses QQQ queries and the same ordering and cutoff semantics.
    *******************************************************************************/
   public List<QRecord> unchained(Instant cutoff, int limit) throws QException
   {
      return (unchained(cutoff, limit, 0L));
   }


   /*******************************************************************************
    ** Settled unchained headers above a swept audit id floor (RDBMS only); every
    ** settled header at or below the floor is already known to be chained.
    *******************************************************************************/
   public List<QRecord> unchained(Instant cutoff, int limit, long floor) throws QException
   {
      if(isRdbms())
      {
         String sql = "SELECT a." + column("audit", "id") + " FROM " + physical("audit") + " a WHERE a." + column("audit", "id") + " > ? AND a."
            + column("audit", "timestamp") + " < ?" + unchainedPredicate() + " ORDER BY a." + column("audit", "timestamp") + ", a." + column("audit", "id")
            + " LIMIT " + limit;
         Map<Long, QRecord> rows = index(in("audit", "id", sqlIds(sql, floor, cutoff)));
         return (rows.values().stream().sorted(Comparator.comparing((QRecord r) -> r.getValueInstant("timestamp"))
            .thenComparing(r -> r.getValueLong("id"))).toList());
      }
      var covered = all(WormAuditTables.CHAIN).stream().filter(r -> "AUDIT".equals(r.getValueString("kind"))).map(r -> r.getValueLong("audit_id")).collect(java.util.stream.Collectors.toSet());
      return (all("audit").stream().filter(r -> r.getValueInstant("timestamp").isBefore(cutoff) && !covered.contains(r.getValueLong("id")))
         .sorted(Comparator.comparing((QRecord r) -> r.getValueInstant("timestamp")).thenComparing(r -> r.getValueLong("id"))).limit(limit).toList());
   }


   /*******************************************************************************
    ** Latest successful retention anchor, or genesis.
    *******************************************************************************/
   public QRecord anchor() throws QException
   {
      List<QRecord> rows = query(WormAuditTables.PURGE, new QQueryFilter(new QFilterCriteria("outcome", QCriteriaOperator.EQUALS, "PURGED"))
         .withOrderBy(new QFilterOrderBy("id", false)).withLimit(1));
      return (rows.isEmpty() ? new QRecord().withValue("anchor_link_id", 0L).withValue("anchor_hash", Hashes.GENESIS) : rows.getFirst());
   }


   /*******************************************************************************
    ** Whether SQL anti-joins are available in this snapshot.
    *******************************************************************************/
   public boolean isRdbms()
   {
      return (transaction instanceof RDBMSTransaction);
   }


   /*******************************************************************************
    ** Only the in-memory backend may use an unbounded completeness index.
    *******************************************************************************/
   public boolean isMemory()
   {
      return ("memory".equals(QContext.getQInstance().getBackendForTable(WormAuditTables.CHAIN).getBackendType()));
   }


   /*******************************************************************************
    ** Fetch one keyset page, never using an offset or a whole-chain read.
    *******************************************************************************/
   public List<QRecord> page(String table, long after, int limit) throws QException
   {
      return (query(table, new QQueryFilter(new QFilterCriteria("id", QCriteriaOperator.GREATER_THAN, after))
         .withOrderBy(new QFilterOrderBy("id", true)).withLimit(limit)));
   }


   /*******************************************************************************
    ** Fetch just the tail row.
    *******************************************************************************/
   public QRecord last(String table) throws QException
   {
      List<QRecord> rows = query(table, new QQueryFilter().withOrderBy(new QFilterOrderBy("id", false)).withLimit(1));
      return (rows.isEmpty() ? null : rows.getFirst());
   }


   /*******************************************************************************
    ** One batched IN query, with memory-backend integer key normalization.
    *******************************************************************************/
   public List<QRecord> in(String table, String field, Collection<Long> ids) throws QException
   {
      if(ids.isEmpty())
      {
         return (List.of());
      }
      boolean integer = QContext.getQInstance().getTable(table).getField(field).getType()
         == com.kingsrook.qqq.backend.core.model.metadata.fields.QFieldType.INTEGER;
      List<Serializable> values = ids.stream().distinct().map(id -> integer ? (Serializable) Math.toIntExact(id) : id).toList();
      return (query(table, new QQueryFilter(new QFilterCriteria(field, QCriteriaOperator.IN, values)).withOrderBy(new QFilterOrderBy("id", true))));
   }


   /*******************************************************************************
    ** Index one bounded batch by primary key.
    *******************************************************************************/
   public static Map<Long, QRecord> index(List<QRecord> rows)
   {
      return (rows.stream().collect(Collectors.toMap(r -> r.getValueLong("id"), r -> r)));
   }


   /*******************************************************************************
    ** Canonicalize already fetched content; a missing detail never triggers a query.
    *******************************************************************************/
   public byte[] canonical(QRecord audit, List<Long> ids, Map<Long, QRecord> details) throws QException
   {
      List<QRecord> rows = new ArrayList<>();
      for(long id : ids)
      {
         QRecord detail = details.get(id);
         if(detail == null || !audit.getValueLong("id").equals(detail.getValueLong("auditId")))
         {
            throw (new QException("audit_detail " + id + " is missing or belongs to another audit"));
         }
         rows.add(detail);
      }
      return (AuditCanonical.bytes(audit, name("auditTable", audit.getValueLong("auditTableId")), name("auditUser", audit.getValueLong("auditUserId")), rows));
   }


   /*******************************************************************************
    ** Poll uncovered details in a bounded time window; memory retains its simple fallback.
    *******************************************************************************/
   public List<QRecord> lateDetails(Instant cutoff, int hours, int limit) throws QException
   {
      return (lateDetails(cutoff, hours, limit, 0L));
   }


   /*******************************************************************************
    ** Uncovered details above a swept detail id floor (RDBMS only). Coverage is a
    ** primary-key probe of the normalized coverage table, never an array scan.
    *******************************************************************************/
   public List<QRecord> lateDetails(Instant cutoff, int hours, int limit, long floor) throws QException
   {
      if(isRdbms())
      {
         String detailId = "d." + column("auditDetail", "id");
         String sql = "SELECT " + detailId + " FROM " + physical("auditDetail") + " d JOIN " + physical("audit")
            + " a ON a." + column("audit", "id") + "=d." + column("auditDetail", "auditId")
            + " WHERE " + detailId + " > ? AND a." + column("audit", "timestamp") + " < ? AND a." + column("audit", "timestamp") + " >= ?"
            + " AND EXISTS (SELECT 1 FROM worm_audit_chain h WHERE h.kind='AUDIT' AND h.audit_id=a." + column("audit", "id") + ")"
            + " AND NOT EXISTS (SELECT 1 FROM " + WormAuditTables.CHAIN_DETAIL + " x WHERE x.detail_id=" + detailId + ") ORDER BY " + detailId + " LIMIT " + limit;
         return (in("auditDetail", "id", sqlIds(sql, floor, cutoff, cutoff.minusSeconds(hours * 3600L))));
      }
      List<QRecord> links = all(WormAuditTables.CHAIN);
      Set<Long> headers = links.stream().filter(r -> "AUDIT".equals(r.getValueString("kind"))).map(r -> r.getValueLong("audit_id")).collect(Collectors.toSet());
      Set<Long> covered = new HashSet<>();
      links.forEach(link -> covered.addAll(detailIds(link)));
      Set<Long> settled = all("audit").stream().filter(a -> headers.contains(a.getValueLong("id")) && a.getValueInstant("timestamp").isBefore(cutoff))
         .map(a -> a.getValueLong("id")).collect(Collectors.toSet());
      return (all("auditDetail").stream().filter(d -> settled.contains(d.getValueLong("auditId")) && !covered.contains(d.getValueLong("id"))).toList());
   }


   /*******************************************************************************
    ** SQL completeness counts all offenders but returns only the first 100 of each type.
    *******************************************************************************/
   public void completeness(Instant cutoff, VerificationResult result) throws QException
   {
      String auditId = "a." + column("audit", "id");
      String time = "a." + column("audit", "timestamp");
      String headers = "SELECT " + auditId + " AS id, (SELECT count(*) FROM worm_audit_chain c WHERE c.kind='AUDIT' AND c.audit_id=" + auditId
         + ") AS coverage FROM " + physical("audit") + " a WHERE " + time + " < ? OR " + time + " IS NULL";
      String detailId = "d." + column("auditDetail", "id");
      String scope = " FROM " + physical("auditDetail") + " d LEFT JOIN " + physical("audit") + " a ON " + auditId + "=d."
         + column("auditDetail", "auditId");
      String details;
      if(isPostgres())
      {
         ///////////////////////////////////////////////////////////////////////
         // Count coverage from the chain itself (the hashed source of truth), //
         // aggregating every link's ids once rather than probing per detail.  //
         ///////////////////////////////////////////////////////////////////////
         details = "SELECT " + detailId + " AS id, coalesce(cv.n, 0) AS coverage" + scope + " LEFT JOIN (" + CHAIN_COVERAGE
            + ") cv ON cv.id=" + detailId + " WHERE " + time + " < ? OR " + time + " IS NULL";
      }
      else
      {
         details = "SELECT " + detailId + " AS id, (SELECT count(*) FROM worm_audit_chain c WHERE POSITION(',' || CAST(" + detailId
            + " AS varchar) || ',' IN ',' || c.detail_ids || ',') > 0) AS coverage" + scope + " WHERE " + time + " < ? OR " + time + " IS NULL";
      }
      reportCoverage(headers, "audit", cutoff, result);
      reportCoverage(details, "audit_detail", cutoff, result);
      coverageTable(result);
   }


   /*******************************************************************************
    ** The coverage table must hold exactly the chain's own detail lists. A
    ** mismatch would let the writer skip or re-chain a detail, so it is a break.
    *******************************************************************************/
   private void coverageTable(VerificationResult result) throws QException
   {
      String table = "SELECT detail_id, chain_id FROM " + WormAuditTables.CHAIN_DETAIL;
      String sql = isPostgres()
         ? "SELECT detail_id, count(*) OVER() FROM ((" + CHAIN_PAIRS + " EXCEPT " + table + ") UNION ALL (" + table + " EXCEPT " + CHAIN_PAIRS
            + ")) mismatch ORDER BY detail_id LIMIT 100"
         : "SELECT x.detail_id, count(*) OVER() FROM " + WormAuditTables.CHAIN_DETAIL + " x WHERE NOT EXISTS (SELECT 1 FROM worm_audit_chain c"
            + " WHERE c.id=x.chain_id AND POSITION(',' || CAST(x.detail_id AS varchar) || ',' IN ',' || c.detail_ids || ',') > 0) ORDER BY x.detail_id LIMIT 100";
      try(PreparedStatement statement = ((RDBMSTransaction) transaction).getConnection().prepareStatement(sql); ResultSet rows = statement.executeQuery())
      {
         long total = 0;
         int reported = 0;
         while(rows.next())
         {
            total = rows.getLong(2);
            result.add(null, null, "audit_detail " + com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier.number(rows.getLong(1))
               + " has a detail coverage row that disagrees with the chain");
            reported++;
         }
         result.omitted(total - reported);
      }
      catch(Exception e)
      {
         throw (AppendOnlyGuard.map(e));
      }
   }


   /*******************************************************************************
    ** Highest id in a core audit table, or 0 when it is empty (RDBMS only).
    *******************************************************************************/
   public long maxId(String table) throws QException
   {
      return (sqlIds("SELECT coalesce(max(" + column(table, "id") + "), 0) FROM " + physical(table)).getFirst());
   }


   /*******************************************************************************
    ** PostgreSQL maintains detail coverage in its chain trigger; other backends
    ** have no trigger, so the writer appends coverage rows itself.
    *******************************************************************************/
   public boolean isPostgres() throws QException
   {
      if(postgres == null)
      {
         try
         {
            postgres = isRdbms() && "PostgreSQL".equals(((RDBMSTransaction) transaction).getConnection().getMetaData().getDatabaseProductName());
         }
         catch(Exception e)
         {
            throw (AppendOnlyGuard.map(e));
         }
      }
      return (postgres);
   }


   /*******************************************************************************
    ** Keep exact offender ids and total counts without materializing the result set.
    *******************************************************************************/
   private void reportCoverage(String source, String table, Instant cutoff, VerificationResult result) throws QException
   {
      String sql = "SELECT id, coverage, count(*) OVER() AS total FROM (" + source + ") offenders WHERE coverage <> 1 ORDER BY id LIMIT 100";
      try(PreparedStatement statement = ((RDBMSTransaction) transaction).getConnection().prepareStatement(sql))
      {
         bindCutoff(statement, 1, cutoff);
         long total = 0;
         int reported = 0;
         try(ResultSet rows = statement.executeQuery())
         {
            while(rows.next())
            {
               long id = rows.getLong(1);
               total = rows.getLong(3);
               result.add(null, table.equals("audit") ? id : null, table + " " + com.kingsrook.qbits.wormaudit.verify.WormAuditVerifier.number(id)
                  + (rows.getLong(2) == 0 ? " is not covered by the chain" : " is covered twice or more by the chain"));
               reported++;
            }
         }
         result.omitted(total - reported);
         if(total > reported)
         {
            result.warn(table + ": " + total + " coverage offenders; first 100 ids reported");
         }
      }
      catch(Exception e)
      {
         throw (AppendOnlyGuard.map(e));
      }
   }


   /*******************************************************************************
    ** Read ids from an anti-join, binding instants by column type and ids as longs.
    *******************************************************************************/
   private List<Long> sqlIds(String sql, Object... parameters) throws QException
   {
      try(PreparedStatement statement = ((RDBMSTransaction) transaction).getConnection().prepareStatement(sql))
      {
         for(int i = 0; i < parameters.length; i++)
         {
            if(parameters[i] instanceof Instant instant)
            {
               bindCutoff(statement, i + 1, instant);
            }
            else
            {
               statement.setLong(i + 1, (Long) parameters[i]);
            }
         }
         List<Long> ids = new ArrayList<>();
         try(ResultSet rows = statement.executeQuery())
         {
            while(rows.next())
            {
               ids.add(rows.getLong(1));
            }
         }
         return (ids);
      }
      catch(Exception e)
      {
         throw (AppendOnlyGuard.map(e));
      }
   }


   /*******************************************************************************
    ** UTC local timestamps for without-tz columns; offset timestamps for timestamptz.
    *******************************************************************************/
   private void bindCutoff(PreparedStatement statement, int index, Instant cutoff) throws Exception
   {
      if(timestampWithZone == null)
      {
         try(var probe = ((RDBMSTransaction) transaction).getConnection().createStatement();
             var rows = probe.executeQuery("SELECT " + column("audit", "timestamp") + " FROM " + physical("audit") + " WHERE 1=0"))
         {
            var metadata = rows.getMetaData();
            timestampWithZone = metadata.getColumnType(1) == Types.TIMESTAMP_WITH_TIMEZONE
               || "timestamptz".equalsIgnoreCase(metadata.getColumnTypeName(1));
         }
      }
      statement.setObject(index, timestampWithZone ? cutoff.atOffset(ZoneOffset.UTC) : LocalDateTime.ofInstant(cutoff, ZoneOffset.UTC));
   }


   /*******************************************************************************
    ** Resolve and quote physical core table names.
    *******************************************************************************/
   private String physical(String table)
   {
      return (WormAuditDdl.identifier(((RDBMSTableBackendDetails) QContext.getQInstance().getTable(table).getBackendDetails()).getTableName()));
   }


   /*******************************************************************************
    ** Resolve and quote physical field names for runtime queries.
    *******************************************************************************/
   private String column(String table, String field)
   {
      String name = QContext.getQInstance().getTable(table).getField(field).getBackendName();
      return (WormAuditDdl.identifier(name == null ? field : name));
   }
}
