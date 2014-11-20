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
package edu.tamu.tcat.account.test;

import java.util.UUID;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.internal.DatabaseAuthUtil;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.db.store.DatabaseAccountStore;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.account.test.internal.Activator;
import edu.tamu.tcat.account.test.mock.MockAccountStore;
import edu.tamu.tcat.account.test.mock.MockEncryptingUuidTokenService;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;
import edu.tamu.tcat.db.exec.sql.SqlExecutor;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

public class AccountTest
{
   private static final String LOGIN_PROVIDER_DB = "db.basic";
   private static final Logger debug = Logger.getLogger(AccountTest.class.getName());

   @Ignore
   @Test
   public void testLogin() throws Exception
   {
      //----
      // stage 1 - get credentials
      
      // presumably, this is the information provided as credentials to log the user in
      String username = "paul.bilnoski";
      String password = "pass";
      
      // The user selected a Login Provider
      String providerId = LOGIN_PROVIDER_DB;
      
      //----
      // stage 2 - authenticate
      
      // instantiate login provider with its configuration and initialize with credentials
      // This app only uses username/password credentials
      CryptoProvider crypto = getCryptoProvider();
      SqlExecutor dbExec = getDbExecutor();
      LoginProvider loginProvider = getLoginProvider(providerId, username, password, crypto, dbExec);
      
      // provider encapsulates everything, so try to log in (or fail)
      LoginData data = loginProvider.login();
      
      debug.info("lpid: " + data.getLoginProviderId());
      debug.info("lpuid: " + data.getLoginUserId());
      
      //----
      // stage 3 - map to account
      Account account = null;
      try
      {
         AccountStore store = getAccountStore();
         account = store.lookup(data);
      }
      catch (AccountNotFoundException nfe)
      {
         debug.info("Account does not exist for provider ["+data.getLoginProviderId()+"] user["+data.getLoginUserId()+"]");
         // here would be a good place to create the account if configured to do so
         // Would need to somehow examine the LoginProvider to see if it allows account creation?
         throw new Exception("Account does not exist. Not creating", nfe);
      }
      catch (Exception e)
      {
         throw new Exception("Failed account lookup", e);
      }
      
      //----
      // stage 4 - "log in" by creating a secure token
      UUID acctId = account.getId();
      TokenService<UUID> tokenService = getTokenService(crypto);
      TokenService.TokenData<UUID> tokenData = tokenService.createTokenData(acctId);
      
      StringBuilder sbCookie = new StringBuilder();
      sbCookie.append("token=").append(tokenData.getToken())
              .append(";expires=").append(tokenData.getExpireStr());
      
      String cookie = sbCookie.toString();
      debug.info("Auth cookie is ["+cookie+"]");

      debug.info("done");
   }
   
   @Ignore
   @Test
   public void testCreateAccount() throws Exception
   {
      DatabaseAccountStore store = getDbAccountStore();
      store.createAccount("neal.audenaert");
   }
   
   @Ignore
   @Test
   public void testCreateAuthn() throws Exception
   {
      DatabaseAuthUtil.AccountRecord data = new DatabaseAuthUtil.AccountRecord();
      data.username = "neal.audenaert";
      data.first = "Neal";
      data.last = "Audenaert";
      data.email = "neala@tamu.edu";
      String passwordRaw = "pass";
      DatabaseAuthUtil.AccountRecord created = DatabaseAuthUtil.createRecord(getCryptoProvider(), getDbExecutor(), data, passwordRaw);
   }
   
   @Ignore
   @Test
   public void testCreateAccountAuthn() throws Exception
   {
      DatabaseAccountStore store = getDbAccountStore();
      store.createAccount("neal.audenaert");
   }
   
   private CryptoProvider getCryptoProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
   
   private SqlExecutor getDbExecutor()
   {
      try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
      {
         SqlExecutor exec = sh.waitForService(SqlExecutor.class, 5_000);
         return exec;
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }
   
   private LoginProvider getLoginProvider(String providerId, String username, String password, CryptoProvider cp, SqlExecutor dbExec)
   {
      if (providerId.equals(LOGIN_PROVIDER_DB))
      {
         DatabaseLoginProvider db = new DatabaseLoginProvider();
         db.init(providerId, username, password, cp, dbExec);
         return db;
      }
      
      throw new IllegalStateException("Unknown provider id: " + providerId);
   }
   
   private AccountStore getAccountStore()
   {
      return new MockAccountStore();
   }
   
   private DatabaseAccountStore getDbAccountStore()
   {
      DatabaseAccountStore store = new DatabaseAccountStore();
      store.bind(getDbExecutor());
      return store;
   }
   
   private TokenService<UUID> getTokenService(CryptoProvider crypto) throws AccountException
   {
      return new MockEncryptingUuidTokenService(crypto);
   }
}
