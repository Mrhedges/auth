package edu.tamu.tcat.oss.account.test;

import java.util.logging.Logger;

import org.junit.Test;

import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.login.provider.db.DatabaseLoginProvider;

public class AccountTest
{
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
      String providerId = "db.basic";
      
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
      
      
      //----
      // stage 4 - "log in" by creating a secure token

      

      debug.info("done");
   }
   
   private LoginProvider getLoginProvider(String providerId, String username, String password)
   {
      if (providerId.equals("db.basic"))
      {
         DatabaseLoginProvider db = new DatabaseLoginProvider();
         db.init(providerId, username, password);
         return db;
      }
      
      throw new IllegalStateException("Unknown provider id: " + providerId);
   }
}