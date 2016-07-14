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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.text.MessageFormat;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.login.AccountRecord;
import edu.tamu.tcat.account.db.login.DatabaseAuthnManager;
import edu.tamu.tcat.account.test.internal.Activator;
import edu.tamu.tcat.account.token.TokenService.TokenData;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;
import edu.tamu.tcat.db.exec.sql.SqlExecutor;
import edu.tamu.tcat.osgi.config.ConfigurationProperties;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

@SuppressWarnings("restriction")
public class DbLoginManagementTest
{
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

         accounts = new DatabaseAuthnManager();
         accounts.bind(crypto);
         accounts.bind(dbExec);
         accounts.bind(config);

         Map<String, Object> props = new HashMap<>();
         props.put(DatabaseAuthnManager.PROP_TOKEN_PROPERTY_KEY, "authn.password.token");
         props.put(DatabaseAuthnManager.PROP_TOKEN_EXPIRES_UNIT_KEY, ChronoUnit.HOURS.name());
         props.put(DatabaseAuthnManager.PROP_TOKEN_EXPIRES_KEY, Long.valueOf(24));
         accounts.activate(props);
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
   public void testGetById() throws AccountException
   {
      AccountRecord data = makeDefaultAccount();
      String passwordRaw = "pass";

      long id = accounts.createRecord(data, passwordRaw).uid;

      AccountRecord resotred = accounts.getRecord(id);
      assertEquals(data.username, resotred.username);
      assertEquals(data.first, resotred.first);
      assertEquals(data.last, resotred.last);
      assertEquals(data.email, resotred.email);
   }

   @Test
   public void testAuthenticatedReset() throws AccountException, InterruptedException
   {
      AccountRecord record = makeDefaultAccount();
      String passwordRaw = "pass";
      String newPasswordRaw = "new_pass";

      accounts.createRecord(record, passwordRaw);
      accounts.setPassword(record.username, passwordRaw, newPasswordRaw);

      // should be able to login with new password
      accounts.authenticate(record.username, newPasswordRaw);

      // should not be able to login with old password
      try {
         accounts.authenticate(record.username, passwordRaw);
         assertFalse("should not authenticate with old password", true);
      }
      catch (AccountException ae)
      {
         // expected
      }

      // should not be able to reset with bad password
      try {
         accounts.setPassword(record.username, passwordRaw, newPasswordRaw);
         assertFalse("should not allow password reset with old password", true);
      }
      catch (AccountException ae)
      {
         // expected
      }
   }

   @Test
   public void testCreateResetToken() throws AccountException
   {
      AccountRecord record = makeDefaultAccount();
      String passwordRaw = "pass";

      accounts.createRecord(record, passwordRaw);

      // it should be possible to create a reset token for the account
      TokenData<AccountRecord> token = accounts.makeResetToken(record.username);

      String tokenStr = token.getToken();
      assertNotNull("The token should not be null", tokenStr);
      assertEquals("The account email should match the original", record.email, token.getPayload().email);

      // should create a new token
      token = accounts.makeResetToken(record.username);
      assertNotNull("The second token should not be null", token.getToken());
      assertEquals("The account email should match the original", record.email, token.getPayload().email);
      assertNotEquals("The first and second tokens should not match", token.getToken(), tokenStr);

      // should no longer be possible to login
      try {
         accounts.authenticate(record.username, passwordRaw);
         assertFalse("Authenticated after password reset", true);
      }
      catch (AccountException ae)
      {
         // expected
      }
   }

   @Test
   public void testTokenBasedReset() throws AccountException
   {
      AccountRecord record = makeDefaultAccount();
      String passwordRaw = "pass";
      String newPasswordRaw = "new pass";

      accounts.createRecord(record, passwordRaw);

      // it should be possible to create a reset token for the account
      TokenData<AccountRecord> token = accounts.makeResetToken(record.username);

      String tokenStr = token.getToken();
      accounts.resetPassword(tokenStr, newPasswordRaw);

      // should be able to login with new password
      accounts.authenticate(record.username, newPasswordRaw);

      // should not be able to login with old password
      try {
         accounts.authenticate(record.username, passwordRaw);
         assertFalse("should not authenticate with old password", true);
      }
      catch (AccountException ae)
      {
         // expected
      }

      // should not be able to reset with bad password
      try {
         accounts.setPassword(record.username, passwordRaw, newPasswordRaw);
         assertFalse("should not allow password reset with old password", true);
      }
      catch (AccountException ae)
      {
         // expected
      }
   }

   @Test
   public void testPasswordResetExpires() throws Exception
   {
      // create short-lived authn manager
      DatabaseAuthnManager accounts = new DatabaseAuthnManager();
      accounts.bind(crypto);
      accounts.bind(dbExec);
      accounts.bind(config);

      Map<String, Object> props = new HashMap<>();
      props.put(DatabaseAuthnManager.PROP_TOKEN_PROPERTY_KEY, "authn.password.token");
      props.put(DatabaseAuthnManager.PROP_TOKEN_EXPIRES_UNIT_KEY, ChronoUnit.SECONDS.name());
      props.put(DatabaseAuthnManager.PROP_TOKEN_EXPIRES_KEY, Long.valueOf(1));
      accounts.activate(props);

      AccountRecord record = makeDefaultAccount();
      String passwordRaw = "pass";

      accounts.createRecord(record, passwordRaw);

      // it should be possible to create a reset token for the account
      TokenData<AccountRecord> token = accounts.makeResetToken(record.username);
      String newPasswordRaw = "new_pass";

      Thread.sleep(1020);
      try {
         accounts.resetPassword(token.getToken(), newPasswordRaw);
         assertFalse("Authenticated after password reset", true);
      }
      catch (AccountException ae)
      {
         // expected
      }
   }
}
