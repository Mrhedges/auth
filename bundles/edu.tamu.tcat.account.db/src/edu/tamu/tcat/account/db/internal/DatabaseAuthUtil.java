package edu.tamu.tcat.account.db.internal;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.oss.db.DbExecTask;
import edu.tamu.tcat.oss.db.DbExecutor;

/**
 * A group of utilities for dealing with database-backed authentication.
 */
public final class DatabaseAuthUtil
{
   //TODO: where to declare these keys? Can't be here, since this is internal.
   //      Could go in some e.t.t.a.db.LoginDataKeys, perhaps?
   /** Named key to request a value from {@link DbLoginData} type: Long  */
   public static final String DATA_KEY_UID = "uid";
   /** Named key to request a value from {@link DbLoginData} type: String */
   public static final String DATA_KEY_USERNAME = "username";
   /** Named key to request a value from {@link DbLoginData} type: String */
   public static final String DATA_KEY_FIRST = "first";
   /** Named key to request a value from {@link DbLoginData} type: String */
   public static final String DATA_KEY_LAST = "last";
   /** Named key to request a value from {@link DbLoginData} type: String */
   public static final String DATA_KEY_EMAIL = "email";
   
   private static final String SQL_TABLENAME = "authn_local";
   private static final String SQL_COL_USERNAME = "user_name";
   private static final String SQL_COL_PWDHASHED = "password_hash";
   
   private DatabaseAuthUtil()
   {
   }
   
   public static class DbLoginData implements LoginData
   {
      private String pid;
      private AccountRecord rec;

      public DbLoginData(String instanceId, AccountRecord rec)
      {
         pid = instanceId;
         this.rec = rec;
      }

      @Override
      public String getLoginProviderId()
      {
         return pid;
      }

      @Override
      public String getLoginUserId()
      {
         return String.valueOf(rec.uid);
      }

      @Override
      public <T> T getData(String key, Class<T> type) throws AccountException
      {
         //HACK: these do not check requested type
         switch (key)
         {
         case DATA_KEY_UID: return (T)Long.valueOf(rec.uid);
         case DATA_KEY_USERNAME: return (T)rec.username;
         case DATA_KEY_FIRST: return (T)rec.first;
         case DATA_KEY_LAST: return (T)rec.last;
         case DATA_KEY_EMAIL: return (T)rec.email;
         }
         return null;
      }
   }
   
   public static class AccountRecord
   {
      public long uid;
      public String username;
      public String passwordHash;
      public String first;
      public String last;
      public String email;
   }

   public static AccountRecord getRecord(final CryptoProvider cp, DbExecutor exec, String name, String passwordRaw) throws Exception
   {
      final AtomicReference<String> nameInput = new AtomicReference<>(name);
      final AtomicReference<String> passwordInput = new AtomicReference<>(passwordRaw);

      // validate credential
      DbExecTask<AccountRecord> task = new DbExecTask<AccountRecord>()
      {
         @Override
         public AccountRecord execute(Connection conn) throws Exception
         {
            String sql = "SELECT * FROM "+SQL_TABLENAME+" WHERE "+SQL_COL_USERNAME+" = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql))
            {
               ps.setString(1, nameInput.get());
               try (ResultSet rs = ps.executeQuery())
               {
                  if (!rs.next())
                     throw new AccountNotFoundException("No user exists with name '"+nameInput.get()+"'");
                  String storedHash = rs.getString(SQL_COL_PWDHASHED);
                  
                  boolean passed = authenticate(cp, passwordInput.get(), storedHash);
                  if (!passed)
                     throw new FailedLoginException("password incorrect");
                  
                  AccountRecord rv = new AccountRecord();
                  rv.uid = rs.getLong("user_id");
                  rv.username = nameInput.get();
                  rv.first = rs.getString("first_name");
                  rv.last = rs.getString("last_name");
                  rv.email = rs.getString("email");
                  
                  // TODO: should this check be done?
                  //if (rs.next())
                  //   throw new AccountNotFoundException("Multiple users exist with name '"+userName+"'");
                  
                  return rv;
               }
            }
            
            //throw new IllegalStateException("Failed accessing user from database");
         }
      };
      
      try
      {
         Future<AccountRecord> f = exec.submit(task);
         // Store the data in fields to be used in commit()
         AccountRecord rec = f.get(10, TimeUnit.SECONDS);
         return rec;
      }
      catch (Exception e)
      {
         throw new AccountException("Failed database processing", e);
      }
   }
   
   public static boolean authenticate(CryptoProvider cp, String passwordRaw, String passwordHashed)
   {
      if (passwordHashed == null)
         //TODO: log: "User ["+username+"] has no stored credential"
         return false;
      PBKDF2 pbkdf2Impl = cp.getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.checkHash(passwordRaw, passwordHashed);
   }
}
