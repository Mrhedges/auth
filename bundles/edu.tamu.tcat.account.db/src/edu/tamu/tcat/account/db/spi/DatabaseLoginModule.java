package edu.tamu.tcat.account.db.spi;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import edu.tamu.tcat.account.db.internal.DatabaseAuthUtil;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.jaas.ServiceProviderCallback;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.oss.db.DbExecutor;

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

/**
 * A JAAS Security Provider Interface {@link LoginModule} implementation backed by a database.
 * <p>
 * This module requires the following callbacks provided by a {@link CallbackHandler}:
 * 
 * <ul><li>{@link NameCallback}</li>
 *     <li>{@link PasswordCallback}</li>
 *     <li>{@link ServiceProviderCallback} containing {@link CryptoProvider} and {@link DbExecutor}</li>
 * </ul>
 * 
 * @see DatabaseLoginProvider for an implementation of {@link edu.tamu.tcat.account.login.LoginProvider}
 */
public class DatabaseLoginModule implements LoginModule
{
   private static final Logger debug = Logger.getLogger(DatabaseLoginModule.class.getName());
   private Subject subject;
   private CallbackHandler cbh;
   
   private boolean didLogin = false;
   private boolean didCommit = false;
   
   // Store
   private DatabaseAuthUtil.AccountRecord record;
   private DatabaseAuthUtil.DbLoginData loginData;
   private Collection<DatabasePrincipal> dbps;
   
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
      loginData = null;
      
      String inputUsername = null;
      String inputPassword = null;
      CryptoProvider inputCrypto = null;
      DbExecutor inputDbExec = null;
      try
      {
         // There are a few library-defined callbacks commonly used
         NameCallback cbName = new NameCallback("Account Name");
         PasswordCallback cbPwd = new PasswordCallback("Account Password", false);
         ServiceProviderCallback cbSP = new ServiceProviderCallback();
         
         cbh.handle(new Callback[] {cbName, cbPwd, cbSP});
         
         inputUsername = cbName.getName();
         char[] chars = cbPwd.getPassword();
         if (chars != null)
         {
            if (chars.length == 0)
               inputPassword = "";
            else
               inputPassword = new String(chars);
         }
         inputCrypto = cbSP.getService(CryptoProvider.class);
         inputDbExec = cbSP.getService(DbExecutor.class);
      }
      catch (UnsupportedCallbackException e)
      {
         throw new LoginException("Callback handler does not support callback: " + e.getCallback());
      }
      catch (IOException e)
      {
         throw new IllegalStateException("Failed handling callbacks", e);
      }
      
      // Just quit if values are invalid
      // invalid username
      if (inputUsername == null || inputUsername.trim().isEmpty())
      {
         debug.fine("Login attempt missing username");
         return true;
      }
      // missing password
      if (inputPassword == null)
      {
         debug.fine("Login attempt missing password");
         return true;
      }
      if (inputCrypto == null)
      {
         debug.fine("Login attempt missing crypto provider");
         return true;
      }
      
      try
      {
         String instanceId = DatabaseLoginModule.class.getName();
         record = DatabaseAuthUtil.getRecord(inputCrypto, inputDbExec, inputUsername, inputPassword);
         if (record == null)
            throw new IllegalStateException("Failed accessing user from database");
         loginData = new DatabaseAuthUtil.DbLoginData(instanceId, record);
      }
      catch (Exception e)
      {
         throw new LoginException("Failed database processing");
      }
      
      didLogin = true;
      return true;
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
      dbps.add(new DatabaseLoginDataPrincipal(record.username, loginData));
      
      Set<Principal> princs = subject.getPrincipals();
      // principals compare using ".equals"
      for (DatabasePrincipal p : dbps)
         if (!princs.contains(p))
            princs.add(p);
      
      // clean up state - no need to retain since principals now exist
      record = null;
      loginData = null;
      
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
         loginData = null;
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
      loginData = null;
      dbps = null;
      
      return true;
   }
}
