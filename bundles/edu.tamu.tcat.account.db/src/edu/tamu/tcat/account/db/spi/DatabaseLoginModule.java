/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.tamu.tcat.account.db.spi;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.NoSuchElementException;
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
import edu.tamu.tcat.db.exec.sql.SqlExecutor;

/**
 * A JAAS Security Provider Interface {@link LoginModule} implementation backed by a database.
 * <p>
 * This module requires the following callbacks provided by a {@link CallbackHandler}:
 * 
 * <ul><li>{@link NameCallback}</li>
 *     <li>{@link PasswordCallback}</li>
 *     <li>{@link ServiceProviderCallback} containing {@link CryptoProvider} and {@link SqlExecutor}</li>
 * </ul>
 * 
 * <p>
 * This module provides the following Principals:
 * 
 * <ul><li>{@link DatabaseLoginDataPrincipal} backed by {@link DatabaseAuthUtil.DbLoginData} </li>
 * </ul>
 * 
 * @see {@link DatabaseLoginProvider} for an implementation of {@link edu.tamu.tcat.account.login.LoginProvider}
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
      SqlExecutor inputDbExec = null;
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
         
         try
         {
            inputCrypto = cbSP.getService(CryptoProvider.class);
            inputDbExec = cbSP.getService(SqlExecutor.class);
         }
         catch (NoSuchElementException nsee)
         {
            throw new LoginException("Service provider callback missing required service: " + nsee.getMessage());
         }
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
