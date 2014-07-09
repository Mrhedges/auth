package edu.tamu.tcat.account.token;

import edu.tamu.tcat.account.AccountException;

public class AccountTokenException extends AccountException
{
   public AccountTokenException()
   {
   }

   public AccountTokenException(String message)
   {
      super(message);
   }

   public AccountTokenException(Throwable cause)
   {
      super(cause);
   }

   public AccountTokenException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public AccountTokenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }
}
