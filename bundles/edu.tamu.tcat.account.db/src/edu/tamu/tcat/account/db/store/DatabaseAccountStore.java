package edu.tamu.tcat.account.db.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.oss.db.DbExecTask;
import edu.tamu.tcat.oss.db.DbExecutor;

/**
 * An implementation of {@link AccountStore} backed by a database. Uses this table definition to store accounts:
 * <pre>
 * CREATE TABLE account
 * (
 *   id bigserial NOT NULL,
 *   account_id text NOT NULL,
 *   title text NOT NULL,
 *   account_type text NOT NULL,
 *   is_active boolean,
 *   is_deleted boolean,
 *   CONSTRAINT id PRIMARY KEY (id)
 * )
 * </pre>
 * 
 * Where:
 * <ul><li><em>id</em> is a per-record identifier</li>
 *     <li><em>account_id</em> is the string form of a {@link UUID} (unique)</li>
 *     <li><em>title</em> is a short display string for the account, such as a user-display-id (not unique)</li>
 *     <li><em>account_type</em> is a string for "user", "group", or "role"</li>
 *     <li><em>is_active</em> is used to disable login</li>
 *     <li><em>is_deleted</em> is used to disable account access but keep the record in the
 *         database for auditing purposes, and is never exposed</li>
 * </ul>
 */
public class DatabaseAccountStore implements AccountStore
{
   static class DatabaseAccount implements Account
   {
      public long id;
      public UUID uuid;
      public String title;
      public String type;
      
      public DatabaseAccount()
      {
      }
      
      @Override
      public UUID getId()
      {
         return uuid;
      }
      
      public String getTitle()
      {
         return title;
      }
      
      public String getType()
      {
         return type;
      }
   }
   
   private static final String SQL_TABLENAME = "account";

   private DbExecutor dbExec;
   
   public void bind(DbExecutor db)
   {
      dbExec = db;
   }
   
   /*
    * Table "account": stores accounts, groups, and roles
    * Table "account_authn": maps accounts that can log in to login provider and login-provider-user-id
    * Table "authn_local": is a "local db" authn provider using "long" for user-id
    * 
    * TODO: create groups for "everyone" and "debug"
    * TODO: create accounts for paul, neal, jesse, matthew
    *       create "account PUT" in the resource, perhaps?
    * TODO: link accounts to local auth in account_authn
    */
   
   @Override
   public Account lookup(LoginData loginData) throws AccountException
   {
      // TODO Auto-generated method stub
      return null;
   }

   @Override
   public Account getAccount(UUID accountId) throws AccountException
   {
      // TODO Auto-generated method stub
      return null;
   }
   
   public Account createAccount(String title) throws AccountException
   {
      if (title == null || title.trim().isEmpty())
         throw new IllegalArgumentException("Account title may not be empty");
      
      DatabaseAccount newAcct = new DatabaseAccount();
      newAcct.uuid = UUID.randomUUID();
      newAcct.title = title;
      newAcct.type = "user";
      
      final AtomicReference<DatabaseAccount> ref = new AtomicReference<>(newAcct);
      
      DbExecTask<DatabaseAccount> task = new DbExecTask<DatabaseAccount>()
      {
         @Override
         public DatabaseAccount execute(Connection conn) throws Exception
         {
            DatabaseAccount acct = ref.get();
            
            String sql = "INSERT INTO "+SQL_TABLENAME+" (account_id, title, account_type, is_active, is_deleted) VALUES (?,?,?,?,?)";
            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS))
            {
               ps.setString(1, acct.uuid.toString());
               ps.setString(2, acct.title);
               ps.setString(3, acct.type);
               ps.setBoolean(4, false); // new accounts are not active
               ps.setBoolean(5, false); // new accounts are not deleted
               
               ps.execute();
               try (ResultSet rs = ps.getGeneratedKeys())
               {
                  if (!rs.next())
                     throw new IllegalStateException("Failed sql insert providing new key");
                  
                  acct.id = rs.getLong("id");
               }
               
               ref.set(acct);
               return acct;
            }
         }
      };
      
      try
      {
         Future<? extends Account> f = dbExec.submit(task);
         // Store the data in fields to be used in commit()
         Account rec = f.get(10, TimeUnit.SECONDS);
         return rec;
      }
      catch (Exception e)
      {
         throw new AccountException("Failed database processing", e);
      }
   }
}
