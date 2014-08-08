package edu.tamu.tcat.account.db.login;

import edu.tamu.tcat.account.db.internal.DatabaseAuthUtil;
import edu.tamu.tcat.account.db.spi.DatabaseLoginModule;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.crypto.CryptoProvider;

/**
 * An implementation of a {@link LoginProvider} which performs authentication against a database.
 * 
 * @see DatabaseLoginModule for an implementation of {@link javax.security.auth.spi.LoginModule} backed by a database.
 */
public class DatabaseLoginProvider implements LoginProvider
{
   private String userName;
   private String pass;
   private String instanceId;
   private CryptoProvider crypto;

   public void init(String providerId, String username, String password, CryptoProvider cp)
   {
      this.instanceId = providerId;
      this.userName = username;
      this.pass = password;
      this.crypto = cp;
   }

   @Override
   public LoginData login() throws AccountLoginException
   {
      try
      {
         DatabaseAuthUtil.AccountRecord rec = DatabaseAuthUtil.getRecord(crypto, userName, pass);
         LoginData rv = new DatabaseAuthUtil.DbLoginData(instanceId, rec);
         return rv;
      }
      catch (Exception e)
      {
         throw new AccountLoginException(e);
      }
   }
}
