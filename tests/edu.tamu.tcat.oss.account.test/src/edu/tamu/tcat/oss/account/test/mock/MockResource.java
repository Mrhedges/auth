package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import javax.ws.rs.BeanParam;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.db.login.DatabaseLoginProvider;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;
import edu.tamu.tcat.oss.account.test.internal.Activator;
import edu.tamu.tcat.oss.db.DbExecutor;

@Path("/mock")
public class MockResource
{
   private static final String LOGIN_PROVIDER_DB = "db.basic";
   
   @POST
   @TokenSecured(payloadType=UUID.class)
   public String doPost(@BeanParam ContextBean bean) throws AccountException
   {
      System.out.println("post");
      UUID uuid = bean.get(UUID.class);
      return "posted: " + uuid;
   }
   
   @POST
   @Path ("/authenticate")
   @Produces (MediaType.APPLICATION_JSON)
   @TokenProviding(payloadType=UUID.class)
   public AccountSDV authenticate(@FormParam("username") String username, @FormParam("password") String password, @BeanParam ContextBean bean) throws AccountException
   {
      if (username == null || username.length() == 0)
         throw new AccountException("Username not specified\n");
      if (password == null || password.length() == 0)
         throw new AccountException("Password not specified\n");
      
      //TODO: later, allow the user to select a Login Provider
      String providerId = LOGIN_PROVIDER_DB;
      
      CryptoProvider crypto = getCryptoProvider();
      DbExecutor dbExec = getDbExecutor();
      LoginProvider loginProvider = getLoginProvider(providerId, username, password, crypto, dbExec);
      
      try
      {
         // provider encapsulates everything, so try to log in (or fail)
         LoginData data = loginProvider.login();
         Account account = getAccountStore().lookup(data);
         
         bean.set(account.getId());
         return new AccountSDV(account);//, getAccountUri(account));
      }
      catch (AccountLoginException | AccountNotFoundException ae)
      {
         throw new ForbiddenException();
      }
   }
   
   /** a serialization data vehicl for {@link Account} */
   static class AccountSDV
   {
      public UUID uuid;
      
      public AccountSDV(Account acct)
      {
         uuid = acct.getId();
      }
   }

   @GET
   @Path ("/reAuthenticate")
   @Produces (MediaType.APPLICATION_JSON)
   //@SignatureSecured(duration = 14)//, unit = ChronoUnit.DAYS)
   @TokenProviding(payloadType=UUID.class)
   public String reAuthenticate(@BeanParam ContextBean bean) throws AccountException
   {
      Account account = bean.get(Account.class);
      //SignatureContext signatureContext = ContextContainingPrincipal.requireContext(context, SignatureContext.class);
      //Account account = Objects.requireNonNull(signatureContext.account);
      
//      final UUID uuid = UUID.randomUUID();
//      // would be looked up
//      Account account = new Account(){
//         @Override
//         public UUID getId()
//         {
//            return uuid;
//         }
//      };
      
      bean.set(account.getId());
      
      return account.toString();
   }
   
   private static AccountStore getAccountStore()
   {
      return new MockAccountStore();
   }
   
   private static CryptoProvider getCryptoProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
   
   private static DbExecutor getDbExecutor()
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
   
   private static LoginProvider getLoginProvider(String providerId, String username, String password, CryptoProvider cp, DbExecutor dbExec)
   {
      if (providerId.equals(LOGIN_PROVIDER_DB))
      {
         DatabaseLoginProvider db = new DatabaseLoginProvider();
         db.init(providerId, username, password, cp, dbExec);
         return db;
      }
      
      throw new IllegalStateException("Unknown provider id: " + providerId);
   }

   
}
