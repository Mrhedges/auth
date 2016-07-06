package edu.tamu.tcat.account.db.login;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;

public class DbLoginData implements LoginData
{
   private String pid;
   private AccountRecord rec;

   public DbLoginData(String instanceId, AccountRecord rec)
   {
      pid = instanceId;
      this.rec = rec;
   }

   @Override
   public String getLoginProviderId()
   {
      return pid;
   }

   @Override
   public String getLoginUserId()
   {
      return String.valueOf(rec.uid);
   }

   @Override
   @SuppressWarnings("unchecked") //HACK: these do not check requested type
   public <T> T getData(String key, Class<T> type) throws AccountException
   {
      switch (key)
      {
      case DatabaseAuthnManager.DATA_KEY_UID: return (T)Long.valueOf(rec.uid);
      case DatabaseAuthnManager.DATA_KEY_USERNAME: return (T)rec.username;
      case DatabaseAuthnManager.DATA_KEY_FIRST: return (T)rec.first;
      case DatabaseAuthnManager.DATA_KEY_LAST: return (T)rec.last;
      case DatabaseAuthnManager.DATA_KEY_EMAIL: return (T)rec.email;
      }
      return null;
   }
}