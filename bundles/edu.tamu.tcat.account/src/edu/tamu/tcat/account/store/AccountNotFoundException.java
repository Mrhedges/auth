package edu.tamu.tcat.account.store;

import edu.tamu.tcat.account.AccountException;

public class AccountNotFoundException extends AccountException
{
   public AccountNotFoundException()
   {
   }

   public AccountNotFoundException(String message)
   {
      super(message);
   }

   public AccountNotFoundException(Throwable cause)
   {
      super(cause);
   }

   public AccountNotFoundException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public AccountNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }
}
