package edu.tamu.tcat.account.login.provider.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;
import edu.tamu.tcat.oss.account.test.CryptoUtil;
import edu.tamu.tcat.oss.account.test.internal.Activator;
import edu.tamu.tcat.oss.db.DbExecTask;
import edu.tamu.tcat.oss.db.DbExecutor;

public class DatabaseLoginProvider implements LoginProvider
{
   private String userName;
   private String pass;
   private String instanceId;
   private CryptoProvider crypto;

   public void init(String providerId, String username, String password, CryptoProvider cp)
   {
      this.instanceId = providerId;
      this.userName = username;
      this.pass = password;
      this.crypto = cp;
   }

   @Override
   public LoginData login() throws AccountLoginException
   {
      try
      {
         AccountRecord rec = getRecord(crypto, userName, pass);
         LoginData rv = new DbLoginData(instanceId, rec);
         return rv;
      }
      catch (Exception e)
      {
         throw new AccountLoginException(e);
      }
   }
   
   static class DbLoginData implements LoginData
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
         case "uid": return (T)Long.valueOf(rec.uid);
         case "username": return (T)rec.username;
         case "first": return (T)rec.first;
         case "last": return (T)rec.last;
         case "email": return (T)rec.email;
         }
         return null;
      }
   }
   
   static class AccountRecord
   {
      long uid;
      String username;
      String passwordHash;
      String first;
      String last;
      String email;
   }

   
   private static AccountRecord getRecord(final CryptoProvider cp, String name, String password) throws Exception
   {
      final AtomicReference<String> nameInput = new AtomicReference<>(name);
      final AtomicReference<String> passwordInput = new AtomicReference<>(password);

      // validate credential
      DbExecTask<AccountRecord> task = new DbExecTask<AccountRecord>()
      {
         @Override
         public AccountRecord execute(Connection conn) throws Exception
         {
            String sql = "SELECT * FROM authn_local WHERE user_name = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql))
            {
               ps.setString(1, nameInput.get());
               try (ResultSet rs = ps.executeQuery())
               {
                  if (!rs.next())
                     throw new AccountNotFoundException("No user exists with name '"+nameInput.get()+"'");
                  String storedHash = rs.getString("password_hash");
                  
                  boolean passed = CryptoUtil.authenticate(cp, passwordInput.get(), storedHash);
                  if (!passed)
                     throw new FailedLoginException("password incorrect");
                  
                  AccountRecord rv = new AccountRecord();
                  rv.uid = rs.getLong("scope_id");
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
      
      try (ServiceHelper sh = new ServiceHelper(Activator.getBundleContext()))
      {
         DbExecutor exec = sh.waitForService(DbExecutor.class, 5_000);
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
}
