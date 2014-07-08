package edu.tamu.tcat.oss.account.test.module;

import java.io.IOException;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import edu.tamu.tcat.oss.account.test.CryptoUtil;
import edu.tamu.tcat.oss.account.test.internal.Activator;
import edu.tamu.tcat.oss.db.DbExecTask;
import edu.tamu.tcat.oss.db.DbExecutor;
import edu.tamu.tcat.oss.osgi.services.util.ServiceHelper;

//TODO: get JAAS authn example working against database
//      write tcat.oss.account wrapper for use with REST
//        Token doLogin(String u, String p);
//        void doLogout(Token t);
//        String getUserInfo(String? key, Token t);
//          back by OSGI service that can cache user subj/principles, flush on logout or on token expiration
//        boolean hasPerm(String? perm, Token t);
//          back by OSGI service that can crawl user/group space and build cache to be flushed on live perm change
//      token: userid, exp time, ip addr, server secret, plus sha256 of uid+exp+ip+secret
//      not exposing Subject and Principals until needed
//      token returned in header, to be update in subsequent requests with moving timeout window

// use pbkdf2impl for password storage, start with 10k rounds and calibrate
// use securetokenimpl for token generation and processing
public class DatabaseLoginModule implements LoginModule
{
   private static final Logger debug = Logger.getLogger(DatabaseLoginModule.class.getName());
   private Subject subject;
   private CallbackHandler cbh;
   
   private boolean didLogin = false;
   private boolean didCommit = false;
   
   // Store
   private AccountRecord record;
   private Collection<DatabasePrincipal> dbps;
   
   static class AccountRecord
   {
      long uid;
      String username;
      String passwordHash;
      String first;
      String last;
      String email;
   }
   
   public DatabaseLoginModule()
   {
      debug.info("created!");
   }
   
   @Override
   public void initialize(Subject subj, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
   {
      this.subject = subj;
      this.cbh = callbackHandler;
      debug.info("init");
   }
   
   @Override
   public boolean login() throws LoginException
   {
      debug.info("login");
      
      // reset state
      didLogin = false;
      record = null;
      
      final AtomicReference<String> name = new AtomicReference<>();
      final AtomicReference<String> passwordInput = new AtomicReference<>();
      try
      {
         List<Callback> cbs = new ArrayList<>();
         // There are a few library-defined callbacks commonly used
         cbs.add(new NameCallback("gimme name!"));
         cbs.add(new PasswordCallback("gimme pass!", false));
         cbh.handle(cbs.toArray(new Callback[cbs.size()]));
         
         String nm = ((NameCallback)cbs.get(0)).getName();
         name.set(nm);
         char[] pwd = ((PasswordCallback)cbs.get(1)).getPassword();
         passwordInput.set(new String(pwd));
      }
      catch (UnsupportedCallbackException e)
      {
         throw new LoginException("Callback handler does not support callback: " + e.getCallback());
      }
      catch (IOException e)
      {
         throw new IllegalStateException("Failed handling callbacks", e);
      }
      
      //String hashed = CryptoUtil.getHash(passwordInput.get());
      
      String nm = name.get();
      // invalid username, just quit
      if (nm == null || nm.trim().isEmpty())
         return true;
      
      try
      {
         record = getRecord(name.get(), passwordInput.get());
         if (record == null)
            throw new IllegalStateException("Failed accessing user from database");
      }
      catch (Exception e)
      {
         throw new LoginException("Failed database processing");
      }
      
      didLogin = true;
      return true;
   }
   
   public static AccountRecord getRecord(String name, String password) throws Exception
   {
      final AtomicReference<String> nameInput = new AtomicReference<>();
      final AtomicReference<String> passwordInput = new AtomicReference<>();

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
                  
                  boolean passed = CryptoUtil.authenticate(passwordInput.get(), storedHash);
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
         throw new LoginException("Failed database processing");
      }
   }

   @Override
   public boolean commit() throws LoginException
   {
      debug.info("commit");
      
      // login did not succeed - clean up internal state
      if (!didLogin)
         return false;
      
      // Store principal as internal state independent from username string
      dbps = new ArrayList<>();
      dbps.add(new DatabaseAccountNamePrincipal(record.username));
      dbps.add(new DatabaseInfoPrincipal(record.email));
      dbps.add(new DatabaseInfoPrincipal(record.first));
      dbps.add(new DatabaseInfoPrincipal(record.last));
      
      Set<Principal> princs = subject.getPrincipals();
      // principals compare using ".equals"
      for (DatabasePrincipal p : dbps)
         if (!princs.contains(p))
            princs.add(p);
      
      // clean up state - no need to retain since principals now exist
      record = null;
      
      didCommit = true;
      return true;
   }

   @Override
   public boolean abort() throws LoginException
   {
      debug.info("abort");
      
      // no state to clean up for failed login
      if (!didLogin)
         return true;
      
      // login success, commit failed
      if (!didCommit)
      {
         record = null;
         return true;
      }
      
      // login and commit succeeded, but some other login module failed, so clean up state
      logout();
      
      return true;
   }

   @Override
   public boolean logout() throws LoginException
   {
      debug.info("logout");
      
      // remove principals added, which will compare via .equals
      Set<Principal> princs = subject.getPrincipals();
      // Allow logout to succeed if login failed, so check for state
      if (dbps != null)
      {
         for (DatabasePrincipal p : dbps)
            princs.remove(p);
      }
      
      didLogin = false;
      didCommit = false;
      
      // Clean up state
      record = null;
      dbps = null;
      
      return true;
   }
}
