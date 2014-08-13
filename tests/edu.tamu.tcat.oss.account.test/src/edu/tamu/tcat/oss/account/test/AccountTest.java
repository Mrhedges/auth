package edu.tamu.tcat.oss.account.test;

import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.uuid.UuidTokenService;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;
import edu.tamu.tcat.oss.account.test.internal.Activator;
import edu.tamu.tcat.oss.account.test.mock.MockEncryptingUuidTokenService;
import edu.tamu.tcat.oss.db.DbExecutor;

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
      DbExecutor dbExec = getDbExecutor();
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
      TokenService.TokenData<UUID> tokenData = tokenService.createTokenData(acctId, 5, TimeUnit.MINUTES);
      
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
   
   private DbExecutor getDbExecutor()
   {
      try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
      {
         DbExecutor exec = sh.waitForService(DbExecutor.class, 5_000);
         return exec;
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }
   
   private LoginProvider getLoginProvider(String providerId, String username, String password, CryptoProvider cp, DbExecutor dbExec)
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
}
