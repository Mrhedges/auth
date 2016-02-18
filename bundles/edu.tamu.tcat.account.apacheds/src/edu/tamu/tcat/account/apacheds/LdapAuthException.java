package edu.tamu.tcat.account.apacheds;

public class LdapAuthException extends LdapException
{
   public LdapAuthException(String message)
   {
      super(message);
   }

   public LdapAuthException(Throwable cause)
   {
      super(cause);
   }

   public LdapAuthException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public LdapAuthException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
   {
      super(message, cause, enableSuppression, writableStackTrace);
   }
}
