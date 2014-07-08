package edu.tamu.tcat.account.login;

public class AccountLoginException extends Exception
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
