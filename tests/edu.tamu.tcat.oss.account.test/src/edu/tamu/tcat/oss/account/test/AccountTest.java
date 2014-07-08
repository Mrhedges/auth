package edu.tamu.tcat.oss.account.test;

import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

import org.junit.Test;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.login.provider.db.DatabaseLoginProvider;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;

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
      LoginProvider loginProvider = getLoginProvider(providerId, username, password);
      
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
      //TODO: get expiration time
      Date expTime = new Date();
      //TODO: pack anything else into this token?
      
      StringBuilder sbToken = new StringBuilder();
      sbToken.append(acctId).append(expTime);
      String token = sbToken.toString();
      debug.info("Auth token is ["+token+"]");

      debug.info("done");
   }
   
   private LoginProvider getLoginProvider(String providerId, String username, String password)
   {
      if (providerId.equals(LOGIN_PROVIDER_DB))
      {
         DatabaseLoginProvider db = new DatabaseLoginProvider();
         db.init(providerId, username, password);
         return db;
      }
      
      throw new IllegalStateException("Unknown provider id: " + providerId);
   }
   
   private AccountStore getAccountStore()
   {
      return new MockAccountStore();
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
