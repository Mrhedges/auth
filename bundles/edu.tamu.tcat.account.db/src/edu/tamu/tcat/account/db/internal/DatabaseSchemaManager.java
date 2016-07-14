package edu.tamu.tcat.account.db.internal;

import static java.text.MessageFormat.format;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.db.exec.sql.SqlExecutor;

public class DatabaseSchemaManager
{
   private static final Logger logger = Logger.getLogger(DatabaseSchemaManager.class.getName());

   private final SqlExecutor exec;
   private final String tablename;

   public DatabaseSchemaManager(String tablename, SqlExecutor exec)
   {
      this.tablename = tablename;
      this.exec = exec;
   }

   public boolean exists() throws AccountException
   {
      Future<Boolean> result = exec.submit(conn -> {
         return Boolean.valueOf(tableExists(conn, tablename));
      });

      return unwrap(result, AccountException.class,
            (ex) -> new AccountException("Failed to deterimin if accounts table exists", ex));
   }

   public boolean create() throws AccountException
   {

      if (exists())
         return false;

      String sql = buildCreateSql();
      Future<Boolean> result = exec.submit((conn) -> createTable(conn, sql));
      return unwrap(result, AccountException.class,
            (ex) -> new AccountException("Failed to create accounts table", ex));
   }

   private <X, EX extends Exception> X unwrap(Future<X> future, Class<EX> exType, Function<Exception, EX> message) throws EX
   {
      try
      {
         return future.get();
      }
      catch (InterruptedException e)
      {
         throw new IllegalStateException(e);
      }
      catch (ExecutionException e)
      {
         Throwable cause = e.getCause();
         if (exType.isInstance(cause))
            throw exType.cast(cause);
         if (RuntimeException.class.isInstance(cause))
            throw RuntimeException.class.cast(cause);

         throw new IllegalStateException(cause);
      }
   }

   private boolean checkColumnsMatch(Connection conn) throws SQLException
   {
      // (20150814) Adapted from
      // http://stackoverflow.com/questions/4336259/query-the-schema-details-of-a-table-in-postgresql
      String sql = "SELECT"
                 +   " a.attname as column,"
                 +   " pg_catalog.format_type(a.atttypid, a.atttypmod) as datatype"
                 + "  FROM pg_catalog.pg_attribute a"
                 + " WHERE a.attnum > 0 AND NOT a.attisdropped"
                 + "   AND a.attrelid = ("
                        + "SELECT c.oid"
                        + "  FROM pg_catalog.pg_class c"
                        + "  LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                        + " WHERE c.relname = ?"
                        + "   AND pg_catalog.pg_table_is_visible(c.oid)"
                 +    ")";

      // NOTE for now, we'll just check that the columns exist and trust that if we have a
      //      table that matches the schema someone knew what they were doing. In theory,
      //      we should check column types to make sure everything works.

      Map<String, ColumnDef> definedColumns = new HashMap<>();
      try (PreparedStatement stmt = conn.prepareStatement(sql))
      {
         stmt.setString(1, tablename);

         ResultSet rs = stmt.executeQuery();
         while (rs.next())
         {
            ColumnDef def = new ColumnDef();
            def.name = rs.getString("column");
            def.type = rs.getString("datatype");

            definedColumns.put(def.name, def);
         }
      }

      // FIXME allow for column definitions
      return definedColumns.isEmpty() ? false : true;
//      return  matchColumType(definedColumns, schema.getIdField(), "^char.+")
//              && matchColumType(definedColumns, schema.getDataField(), "^json")
//              && matchColumType(definedColumns, schema.getCreatedField(), "^time.+")
//              && matchColumType(definedColumns, schema.getModifiedField(), "^time.+")
//              &&  matchColumType(definedColumns, schema.getRemovedField(), "^time.+");
   }

   private boolean matchColumType(Map<String, ColumnDef> definedColumns, String fname, String regex)
   {
      if (fname == null)
         return true;      // this column is not used - does not matter if it is in the table

      ColumnDef columnDef = definedColumns.get(fname);
      return columnDef != null && columnDef.type.matches(regex);
   }

   private static class ColumnDef
   {
      public String name;
      public String type;

      public boolean allowNull = true;
      public String defaultValue = "null";
   }

   private static boolean tableExists(Connection conn, String tablename) throws SQLException
   {
      // (20150814) Adapted from
      // http://stackoverflow.com/questions/20582500/how-to-check-if-a-table-exists-in-a-given-schema
      String sql = "SELECT EXISTS ("
            + "SELECT 1 FROM pg_catalog.pg_class c"
            + "  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
            + " WHERE c.relname = ? AND c.relkind = 'r'"
            + ")";

      try (PreparedStatement stmt = conn.prepareStatement(sql))
      {
         stmt.setString(1, tablename);

         ResultSet rs = stmt.executeQuery();
         rs.next();
         return Boolean.valueOf(rs.getBoolean(1));
      }
   }

   // TODO truncate, drop?

   public static class DATE_COLUMN_STRATEGY
   {
      public String getCreateDefinition(ColumnDef def)
      {
         return MessageFormat.format("{0} TIMESTAMP DEFAULT NULL", def.name);
      }
   }
   private String buildCreateSql()
   {
      return format("CREATE TABLE {0} (\n" +
            "   user_id BIGSERIAL NOT NULL,\n" +
            "   user_name VARCHAR NOT NULL,\n" +
            "   password_hash VARCHAR,\n" +
            "   reset_hash VARCHAR DEFAULT NULL,\n" +
            "   first_name VARCHAR,\n" +
            "   last_name VARCHAR,\n" +
            "   email VARCHAR\n" +
            ")", tablename);
   }

   private Boolean createTable(Connection conn, String sql) throws AccountException, SQLException
   {
      if (tableExists(conn, tablename))
         throw new AccountException(MessageFormat.format("A table with this name {0} already exists.", tablename));

      logger.log(Level.INFO, "Creating database tables for repository.\n" + sql);
      try (Statement stmt = conn.createStatement())
      {
         stmt.executeUpdate(sql);
      }

      return Boolean.valueOf(true);
   }
}
