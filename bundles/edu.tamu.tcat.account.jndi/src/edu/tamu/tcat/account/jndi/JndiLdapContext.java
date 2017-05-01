package edu.tamu.tcat.account.jndi;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;

import edu.tamu.tcat.account.AccountException;

/**
 * A thin wrapper to initialize an {@link LdapContext} and hold it as {@link AutoCloseable}. This is not meant
 * to replace the API, but exposes the wrapped context via {@link #getContext()}. This wrapper in particular handles
 * TLS and SSL connections, which are more complex than normal connections.
 */
public class JndiLdapContext implements AutoCloseable
{
   private static final Logger logger = Logger.getLogger(JndiLdapContext.class.getName());
   private LdapContext ctx;
   private StartTlsResponse tls;
   private Properties env;

   /**
    * Create a new closeable context. Hosts provided may be of the format "ldap://host:port/", "ldaps://host:port/", or with
    * multiple as "ldap://host1:port/ ldap://host2:port/" for the library to internally fall-back when attempting to connect.
    *
    * @param host May be space-separated to attempt multiple hosts
    * @param port
    * @param adminAccountDn
    * @param adminAccountPassword
    * @param useSsl
    * @param useTls
    */
   public JndiLdapContext(String ldapURLs,
                          String adminAccountDn,
                          String adminAccountPassword,
                          boolean useSsl,
                          boolean useTls)
   {
      if (useSsl && useTls)
         throw new IllegalArgumentException("Must use either SSL or TLS or neither");

      env = new Properties();
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      //NOTE: this is important, because it ensures objectGUID is retrieved as byte[] and not String
      env.put("java.naming.ldap.attributes.binary", "objectGUID");
      env.put(Context.PROVIDER_URL, ldapURLs);
      if (useSsl)
         env.put(Context.SECURITY_PROTOCOL, "ssl");
      // This env var is ignored, but may help for debugging
      if (useTls)
         env.put(Context.SECURITY_PROTOCOL, "tls");

      try
      {
         // First, bind anonymously, then send credentials
         ctx = new InitialLdapContext(env, null);

         if (useTls)
         {
            tls = (StartTlsResponse)ctx.extendedOperation(new StartTlsRequest());
            tls.negotiate();
         }

         if (adminAccountDn != null)
         {
            // Set user/pass for LDAP access
            ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
            ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, adminAccountDn);
            ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, adminAccountPassword);
         }

         // Force connection/bind to use established credentials instead of failing later on first use
         ctx.reconnect(null);
      }
      catch (Exception e)
      {
         Exception c = null;
         try
         {
            close();
         }
         catch (Exception ex2)
         {
            c = ex2;
         }
         AccountException ae = new AccountException("Failed to initialize LDAP context", e);
         if (c != null)
            ae.addSuppressed(c);
         throw ae;
      }
   }

   @Override
   public void close() throws Exception
   {
      //Exception tlsEx = null;
      if (tls != null)
      {
         try
         {
            tls.close();
         }
         catch (Exception e)
         {
            //tlsEx = e;
            logger.log(Level.WARNING, "Failed closing LDAP resource", e);
         }
      }
      try
      {
         ctx.close();
      }
      catch (Exception e)
      {
         // Not too concerned if the resources fail to close; don't want that to throw exceptions
         // that could be masked in try-with-resources or force operations to fail that actually succeeded or
         // have to nest a try/catch within try-with-resources to handle this case as a soft failure.
         // Hard failure code to throw is left in and commented in case it is useful.
         logger.log(Level.WARNING, "Failed closing LDAP resource", e);
         //AccountException ae = new AccountException("Failed closing LDAP resources", e);
         //if (tlsEx != null)
         //   ae.addSuppressed(tlsEx);
         //throw ae;
      }
      //if (tlsEx != null)
      //   throw new AccountException("Failed closing LDAP resources", tlsEx);
   }

   public LdapContext getContext()
   {
      return ctx;
   }

   public boolean authenticate(String dn, String password)
   {
      if (dn == null || dn.trim().isEmpty())
         throw new IllegalArgumentException("Failed LDAP authentication attempt. Distinguished Name not supplied.");
      if (password == null || password.trim().isEmpty())
         throw new IllegalArgumentException("Failed LDAP authentication attempt. Password not supplied.");
      try
      {
         // Bind (and release) another context with given DN and password
         try (JndiLdapContext ctxAuth = new JndiLdapContext(env.getProperty(Context.PROVIDER_URL), dn, password, tls == null, tls != null))
         {
            return true;
         }
      }
      catch (Exception e)
      {
         logger.log(Level.WARNING, "Failed LDAP authentication attempt", e);
         return false;
      }
   }
}
