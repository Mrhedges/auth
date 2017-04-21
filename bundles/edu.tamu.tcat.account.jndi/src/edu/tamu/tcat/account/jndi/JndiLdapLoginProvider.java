package edu.tamu.tcat.account.jndi;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;

public class JndiLdapLoginProvider implements LoginProvider
{
   private static final Logger debug = Logger.getLogger(JndiLdapLoginProvider.class.getName());
   public static final String PROVIDER_ID = "tcatLdapLoginProvider";
   private String host;
   private int port;
   private String adminAccountDn;
   private String adminAccountPassword;
   private boolean useSsl;
   private boolean useTls;

   private String username;
   private String password;
   private String instanceId;

   private List<String> searchOUs;

   public JndiLdapLoginProvider(String host, int port, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls)
   {
      this.host = host;
      this.port = port;
      this.adminAccountDn = adminAccountDn;
      this.adminAccountPassword = adminAccountPassword;
      this.useSsl = useSsl;
      this.useTls = useTls;
   }

   public void init(String username, String password, String instanceId, List<String> searchOUs)
   {
      this.searchOUs = new ArrayList<>();
      if (searchOUs != null)
         this.searchOUs.addAll(searchOUs);
      this.username = Objects.requireNonNull(username);
      this.password = Objects.requireNonNull(password);
      this.instanceId = Objects.requireNonNull(instanceId);
   }

   @Override
   public LoginData login()
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         // Search the directory
         String filter = "(sAMAccountName={0})";
         SearchControls ctls = new SearchControls();
         ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
         ctls.setReturningAttributes(new String[0]);
         ctls.setReturningObjFlag(true);
         String dn = null;
         for (String base : searchOUs)
         {
            NamingEnumeration<SearchResult> results = ctx.getContext().search(base, filter, new String[] { username }, ctls);
            try
            {
               if (results.hasMore())
               {
                  SearchResult result = results.next();
                  dn = result.getNameInNamespace();

                  // If there are more results, got multiple matches, so should fail
                  if (results.hasMore())
                  {
                     dn = null;
                     debug.warning("Found multiple LDAP entries matching name ["+username+"] in OU ["+base+"]");
                  }

                  if (dn != null)
                     break;
               }
            }
            finally
            {
               try {
                  results.close();
               }
               catch (Exception e) {
                  debug.log(Level.WARNING, "Failed closing LDAP resource", e);
               }
            }
         }

         if (dn == null)
            return null;

         // Step 3: Bind another context with found DN and given password
         Hashtable<Object,Object> envAuth = (Hashtable)ctx.getContext().getEnvironment().clone();
         envAuth.put(Context.SECURITY_PRINCIPAL, dn);
         envAuth.put(Context.SECURITY_CREDENTIALS, password);
         try
         {
            // If this fails, the password was invalid, so auth fails
            LdapContext ctxAuth = new InitialLdapContext(envAuth, null);
            try
            {
               JndiLdapLoginData rv = new JndiLdapLoginData(ctx.getContext(), dn, PROVIDER_ID);
               return rv;
            }
            finally
            {
               try
               {
                  ctxAuth.close();
               }
               catch (Exception e)
               {
                  debug.log(Level.WARNING, "Failed closing LDAP resource", e);
               }
            }
         }
         catch (Exception e)
         {
            // This is expected if authn fails, so log as FINE
            debug.log(Level.FINE, "Failed LDAP authentication", e);
         }
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed to initialize LDAP authentication attempt", e);
      }
      return null;
   }

   /**
    * Get the {@link LoginData} representing details of an identity, as requested by {@link #username}, or {@code null}. This is useful to look up
    * details, for example when performing password reset handshake operations.
    */
   public LoginData unauthGetDetails(String username, String instanceId, List<String> searchOUs)
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         // Search the directory
         String filter = "(sAMAccountName={0})";
         SearchControls ctls = new SearchControls();
         ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
         ctls.setReturningAttributes(new String[0]);
         ctls.setReturningObjFlag(true);
         String dn = null;
         for (String base : searchOUs)
         {
            NamingEnumeration<SearchResult> results = ctx.getContext().search(base, filter, new String[] { username }, ctls);
            try
            {
               if (results.hasMore())
               {
                  SearchResult result = results.next();
                  dn = result.getNameInNamespace();

                  // If there are more results, got multiple matches, so should fail
                  if (results.hasMore())
                  {
                     dn = null;
                     debug.warning("Found multiple LDAP entries matching name ["+username+"] in OU ["+base+"]");
                  }

                  if (dn != null)
                     break;
               }
            }
            finally
            {
               try {
                  results.close();
               }
               catch (Exception e) {
                  debug.log(Level.WARNING, "Failed closing LDAP resource", e);
               }
            }
         }

         if (dn == null)
            return null;

         JndiLdapLoginData rv = new JndiLdapLoginData(ctx.getContext(), dn, PROVIDER_ID);
         return rv;
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed LDAP data retrieval", e);
      }
      return null;
   }

   public void setAttribute(String dn, String attributeName, Object value)
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         Attributes attrs = new BasicAttributes(attributeName, value);
         // REPLACE_ATTRIBUTE will remove-all if value is null, or create-or-replace all existing values
         ctx.getContext().modifyAttributes(dn, DirContext.REPLACE_ATTRIBUTE, attrs);
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed LDAP attribute update '"+attributeName+"' for '"+dn+"'", e);
      }
   }

   public String getDN(byte[] objectGUID, String searchOU)
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         String guidStr = ADDataUtils.toGuidBindingString(objectGUID);
         String dn = ctx.getContext().getAttributes(guidStr).get("distinguishedName").get().toString();
         return dn;
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed LDAP data retrieval", e);
      }
      return null;
   }

   public Object getAttributeValue(String dn, String attributeName)
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         Attributes attrs = ctx.getContext().getAttributes(dn);
         Attribute attr = attrs.get(attributeName);
         if (attr == null)
            return null;
         return attr.get();
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed LDAP attribute get '"+attributeName+"' for '"+dn+"'", e);
      }
      return null;
   }

   /**
    * Check if the credentials in this login provider match an LDAP account. This API is used to determine
    * if the account exists in the system before attempting to create it if the application has such capability.
    */
   public boolean identityExists()
   {
      try (JndiLdapContext ctx = new JndiLdapContext(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         // Search the directory
         String filter = "(sAMAccountName={0})";
         SearchControls ctls = new SearchControls();
         ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
         ctls.setReturningAttributes(new String[0]);
         ctls.setReturningObjFlag(true);
         String dn = null;
         for (String base : searchOUs)
         {
            NamingEnumeration<SearchResult> results = ctx.getContext().search(base, filter, new String[] { username }, ctls);
            try
            {
               if (results.hasMore())
               {
                  SearchResult result = results.next();
                  dn = result.getNameInNamespace();

                  // If there are more results, got multiple matches, so should fail
                  if (results.hasMore())
                     debug.warning("Found multiple LDAP entries matching name ["+username+"] in OU ["+base+"]");

                  if (dn != null)
                     return true;
               }
            }
            finally
            {
               try {
                  results.close();
               }
               catch (Exception e) {
                  debug.log(Level.WARNING, "Failed closing LDAP resource", e);
               }
            }
         }
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed to initialize LDAP existence query attempt", e);
      }
      return false;
   }
}
