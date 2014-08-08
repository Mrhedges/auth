package edu.tamu.tcat.oss.account.test;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.junit.Test;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.uuid.UuidTokenService;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.TokenException;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

public class AccountTest
{
   private static final String LOGIN_PROVIDER_DB = "db.basic";
   private static final Logger debug = Logger.getLogger(AccountTest.class.getName());

//   @Ignore
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
      LoginProvider loginProvider = getLoginProvider(providerId, username, password, crypto);
      
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
         account = store.lookup(data.getLoginProviderId(), data.getLoginUserId());
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
      TokenService.TokenData tokenData = tokenService.createTokenData(acctId, 5, TimeUnit.MINUTES);
      
      StringBuilder sbCookie = new StringBuilder();
      sbCookie.append("token=").append(tokenData.getToken())
              .append(";expires=").append(tokenData.getExpireStr());
      
      String cookie = sbCookie.toString();
      debug.info("Auth cookie is ["+cookie+"]");

      debug.info("done");
   }
   
   private CryptoProvider getCryptoProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
   
   private LoginProvider getLoginProvider(String providerId, String username, String password, CryptoProvider cp)
   {
      if (providerId.equals(LOGIN_PROVIDER_DB))
      {
         DatabaseLoginProvider db = new DatabaseLoginProvider();
         db.init(providerId, username, password, cp);
         return db;
      }
      
      throw new IllegalStateException("Unknown provider id: " + providerId);
   }
   
   private AccountStore getAccountStore()
   {
      return new MockAccountStore();
   }
   
   private UuidTokenService getTokenService(CryptoProvider crypto) throws AccountException
   {
      return new MockEncryptingUuidTokenService(crypto);
   }
   
   static class MockAccountStore implements AccountStore
   {
      @Override
      public Account lookup(String loginProviderId, String loginProviderUserId) throws AccountException
      {
         MockAccount acct = new MockAccount();
         acct.pid = loginProviderUserId;
         acct.uid = UUID.randomUUID();
         return acct;
      }
   }
   
   static class MockAccount implements Account
   {
      String pid;
      UUID uid;
      
      @Override
      public UUID getId()
      {
         return uid;
      }
   }
   
   static class MockTokenData implements TokenService.TokenData
   {
      private String token;
      private String expireStr;

      public MockTokenData(String t, String expStr)
      {
         token = t;
         expireStr = expStr;
      }
      
      @Override
      public String getToken()
      {
         return token;
      }

      @Deprecated
      @Override
      public String getExpireStr()
      {
         return expireStr;
      }
   }
   
   static class MockUuidTokenService implements UuidTokenService
   {
      @Override
      public TokenService.TokenData createTokenData(UUID uuid, long expiresIn, TimeUnit expiresInUnit) throws AccountTokenException
      {
         return new MockTokenData(uuid.toString(), String.valueOf(expiresIn) + "." + expiresInUnit.toString());
      }

      @Override
      public UUID unpackToken(String token) throws AccountTokenException
      {
         return UUID.fromString(token);
      }
   }
   
   static class MockEncryptingUuidTokenService implements UuidTokenService
   {
      final String keyb64_128 = "blahDiddlyBlahSchmacko";
      final String keyb64_256 = "blahDiddlyBlahSchmackety+ABitLongerThanThat+";
      private final SecureToken secureToken;
      
      public MockEncryptingUuidTokenService(CryptoProvider cryptoProvider) throws AccountTokenException
      {
         byte[] key;
         try
         {
            key = Base64.getDecoder().decode(keyb64_128);
         }
         catch (Exception e)
         {
            throw new AccountTokenException("Could not decode token key", e);
         }
         try
         {
            secureToken = cryptoProvider.getSecureToken(key);
         }
         catch (Exception e)
         {
            throw new AccountTokenException("Could not construct secure token", e);
         }
      }
      
      @Override
      public TokenService.TokenData createTokenData(UUID id, long expiresIn, TimeUnit expiresInUnit) throws AccountTokenException
      {
         ByteBuffer buffer = ByteBuffer.allocate(4 + 8 + 16);
         ZonedDateTime now = ZonedDateTime.now();
         ZonedDateTime expires = now.plus(2, ChronoUnit.WEEKS);
         buffer.putInt(1);
         buffer.putLong(Instant.from(expires).toEpochMilli());
         buffer.putLong(id.getMostSignificantBits());
         buffer.putLong(id.getLeastSignificantBits());
         buffer.flip();
         try
         {
            String stok = secureToken.getToken(buffer);
            String exp = DateTimeFormatter.ISO_ZONED_DATE_TIME.format(expires);
            return new MockTokenData(stok, exp);
         }
         catch (TokenException e)
         {
            throw new AccountTokenException("Could not create token", e);
         }
      }
      
      @Override
      public UUID unpackToken(String token) throws AccountTokenException
      {
         return UUID.fromString(token);
      }
   }
}
