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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.IntStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.login.AccountRecord;
import edu.tamu.tcat.account.db.login.DatabaseAuthnManager;
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
import edu.tamu.tcat.osgi.config.ConfigurationProperties;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

public class AccountTest
{
   private static final String LOGIN_PROVIDER_DB = "db.basic";
   private static final Logger debug = Logger.getLogger(AccountTest.class.getName());

   private CryptoProvider crypto;
   private SqlExecutor dbExec;
   private ConfigurationProperties config;
   private DatabaseAuthnManager accounts;

   @Before
   public void setup()
   {
      try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
      {
         config = sh.waitForService(ConfigurationProperties.class, 5_000);
         dbExec = sh.waitForService(SqlExecutor.class, 5_000);
         crypto = new BouncyCastleCryptoProvider();

         accounts = DatabaseAuthnManager.instantiate(config, dbExec, crypto);
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }

   @After
   public void teardown()
   {
      dbExec.submit(conn -> {
         try (PreparedStatement ps = conn.prepareStatement("TRUNCATE TABLE authn_local"))
         {
            ps.executeUpdate();
            return null;
         }
      });
   }

   public static String makeSecureKey(int keySize)
   {
      if (!IntStream.of(128, 196, 256).anyMatch(k -> k == keySize))
         throw new IllegalArgumentException(MessageFormat.format("Invalid key size {0}. Require 128, 196 or 256 bit keys.", keySize));

      byte[] bytes = new byte[keySize / 8];
      new SecureRandom().nextBytes(bytes);

      return Base64.getEncoder().encodeToString(bytes);
   }

   @Test
   public void testCreateAuthn() throws Exception
   {
      AccountRecord data = makeDefaultAccount();
      String passwordRaw = "pass";

      AccountRecord record = accounts.createRecord(data, passwordRaw);
      assertEquals(data.username, record.username);
      assertEquals(data.first, record.first);
      assertEquals(data.last, record.last);
      assertEquals(data.email, record.email);
   }

   private AccountRecord makeDefaultAccount()
   {
      AccountRecord data = new AccountRecord();
      data.username = "neal.audenaert";
      data.first = "Neal";
      data.last = "Audenaert";
      data.email = "neala@tamu.edu";
      return data;
   }

   @Test
   public void testAuthenticate() throws Exception
   {
      AccountRecord data = makeDefaultAccount();
      String passwordRaw = "pass";

      AccountRecord record = accounts.createRecord(data, passwordRaw);

      AccountRecord authenticated = accounts.authenticate(data.username, passwordRaw);
      assertEquals(record.uid, authenticated.uid);

      try {
         accounts.authenticate(data.username, "badPass");
         assertFalse("Authenticated on bad password", true);
      }
      catch (AccountException ae)
      {
         // expected
      }

      try {
         accounts.authenticate("bad.username", passwordRaw);
         assertFalse("Authenticated on bad username", true);
      }
      catch (AccountException ae)
      {
         // expected
      }
   }

   @Test
   public void testGetById()
   {
      assertFalse("not implemented", true);
   }

   @Test
   public void testCreateResetToken()
   {
      assertFalse("not implemented", true);
   }

   @Test
   public void testPasswordResetExpires()
   {
      assertFalse("not implemented", true);
   }

   @Test
   public void testAuthenticatedReset()
   {
      assertFalse("not implemented", true);
   }

   @Test
   public void testTokenBasedReset()
   {
      assertFalse("not implemented", true);
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
   private ConfigurationProperties getConfig()
   {
      try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
      {
         ConfigurationProperties config = sh.waitForService(ConfigurationProperties.class, 5_000);
         return config;
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
         db.init(providerId, username, password, accounts);
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
