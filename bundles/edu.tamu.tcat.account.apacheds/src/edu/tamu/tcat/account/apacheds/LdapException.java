package edu.tamu.tcat.account.apacheds;

public class LdapException extends Exception
{
   public LdapException(String message)
   {
      super(message);
   }

   public LdapException(Throwable cause)
   {
      super(cause);
   }

   public LdapException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public LdapException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }

}
