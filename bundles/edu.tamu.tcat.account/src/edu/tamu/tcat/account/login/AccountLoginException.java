package edu.tamu.tcat.account.login;

import edu.tamu.tcat.account.AccountException;

public class AccountLoginException extends AccountException
{
   public AccountLoginException()
   {
   }

   public AccountLoginException(String message)
   {
      super(message);
   }

   public AccountLoginException(Throwable cause)
   {
      super(cause);
   }

   public AccountLoginException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public AccountLoginException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }
}
