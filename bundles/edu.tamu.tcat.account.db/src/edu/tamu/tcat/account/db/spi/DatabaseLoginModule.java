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
import java.util.stream.Collectors;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import edu.tamu.tcat.account.db.login.AccountRecord;
import edu.tamu.tcat.account.db.login.DatabaseAuthnManager;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.db.login.DbLoginData;
import edu.tamu.tcat.account.jaas.ServiceProviderCallback;

/**
 * A JAAS Security Provider Interface {@link LoginModule} implementation backed by a database.
 * <p>
 * This module requires the following callbacks provided by a {@link CallbackHandler}:
 *
 * <ul><li>{@link NameCallback}</li>
 *     <li>{@link PasswordCallback}</li>
 *     <li>{@link ServiceProviderCallback} containing {@link DatabaseAuthnManager}</li>
 * </ul>
 *
 * <p>
 * This module provides the following Principals:
 *
 * <ul><li>{@link DatabaseLoginDataPrincipal} backed by {@link DbLoginData} </li>
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
   private AccountRecord record;
   private DbLoginData loginData;
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

      // There are a few library-defined callbacks commonly used
      NameCallback cbName = new NameCallback("Account Name");
      PasswordCallback cbPwd = new PasswordCallback("Account Password", false);
      ServiceProviderCallback cbSP = new ServiceProviderCallback();

      execCallbackHandler(new Callback[] {cbName, cbPwd, cbSP});

      String inputUsername = cbName.getName();
      String inputPassword = getPassword(cbPwd);
      DatabaseAuthnManager authnManager = getAuthnManager(cbSP);

      if (!checkCredentials(inputUsername, inputPassword))
         return true;      // Just quit if values are invalid

      doLogin(authnManager, inputUsername, inputPassword);

      didLogin = true;
      return true;
   }

   private void execCallbackHandler(Callback[] callbacks) throws LoginException
   {
      try
      {
         cbh.handle(callbacks);
      }
      catch (UnsupportedCallbackException e)
      {
         throw new LoginException("Callback handler does not support callback: " + e.getCallback());
      }
      catch (IOException e)
      {
         throw new IllegalStateException("Failed handling callbacks", e);
      }
   }

   private String getPassword(PasswordCallback cbPwd)
   {
      char[] chars = cbPwd.getPassword();
      if (chars == null)
         return null;

      return (chars.length == 0) ? "" : new String(chars);
   }

   private DatabaseAuthnManager getAuthnManager(ServiceProviderCallback cbSP) throws LoginException
   {
      DatabaseAuthnManager authnManager;
      try
      {
         authnManager = cbSP.getService(DatabaseAuthnManager.class);
      }
      catch (NoSuchElementException nsee)
      {
         throw new LoginException("Service provider callback missing required service: " + nsee.getMessage());
      }
      return authnManager;
   }

   /**
    * Checks the supplied username and password to ensure that they are valid.
    *
    * @param inputUsername Must be non-null and non-empty
    * @param inputPassword Must be non-null (may be empty)
    * @return <code>false</code> if the supplied values are not true. In this case, the login
    *       should simply exit.
    */
   private boolean checkCredentials(String inputUsername, String inputPassword)
   {
      if (inputUsername == null || inputUsername.trim().isEmpty())
      {
         debug.fine("Login attempt missing username");
         return false;
      }

      if (inputPassword == null)
      {
         debug.fine("Login attempt missing password");
         return false;
      }

      return true;
   }

   private void doLogin(DatabaseAuthnManager authnManager, String inputUsername, String inputPassword) throws LoginException
   {
      try
      {
         String instanceId = DatabaseLoginModule.class.getName();
         record = authnManager.authenticate(inputUsername, inputPassword);
         if (record == null)
            throw new IllegalStateException("Failed accessing user from database");
         loginData = new DbLoginData(instanceId, record);
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
      dbps.add(new DatabaseLoginDataPrincipal(record.username, loginData));

      // principals compare using ".equals"
      Set<Principal> princs = subject.getPrincipals();
      princs.addAll(dbps.stream()
                        .filter(p -> !princs.contains(p))
                        .collect(Collectors.toSet()));

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
