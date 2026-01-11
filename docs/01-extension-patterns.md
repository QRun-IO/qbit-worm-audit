# Extension Patterns

## Table Customizers

Add behavior to existing tables:

```java
public class AuditTableCustomizer
{
   public void customize(QTableMetaData table)
   {
      table.withField(new QFieldMetaData("createdAt", QFieldType.DATE_TIME));
      table.withField(new QFieldMetaData("modifiedAt", QFieldType.DATE_TIME));

      table.withCustomizer(
         TableCustomizers.PRE_INSERT_RECORD,
         new QCodeReference(AuditPreInsert.class));
   }
}
```

## Action Customizers

Wrap actions with additional behavior:

```java
public class LoggingActionWrapper implements PreInsertRecordInterface
{
   @Override
   public void preInsertRecord(InsertInput input, QRecord record) throws QException
   {
      LOG.info("Inserting record", logPair("table", input.getTableName()));
   }
}
```

## Config Validation

Validate that required components exist:

```java
@Override
public void validate(QInstance qInstance, List<String> errors)
{
   if(qInstance.getTable(targetTableName) == null)
   {
      errors.add("Target table required: " + targetTableName);
   }
}
```

## When to Use Extension QBits

- Adding audit logging to tables
- Implementing authentication/authorization
- Adding encryption to fields
- Custom validation rules
- Performance monitoring
