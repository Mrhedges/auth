package edu.tamu.tcat.account.db.spi;

import java.util.Objects;

import edu.tamu.tcat.account.jaas.LoginDataPrincipal;
import edu.tamu.tcat.account.login.LoginData;

/**
 * Encapsulates an account, using the name as the principal and encapsulating a {@link LoginData}
 */
public class DatabaseLoginDataPrincipal extends DatabasePrincipal implements LoginDataPrincipal
{
   private final LoginData data;

   public DatabaseLoginDataPrincipal(String name, LoginData data)
   {
      super(name);
      
      Objects.requireNonNull(data, "Login Data may not be null");
      this.data = data;
   }
   
   @Override
   public LoginData getLoginData()
   {
      return data;
   }
}
