package edu.tamu.tcat.account.jndi;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;

public class JndiLdapLoginProvider implements LoginProvider
{
   private static final Logger debug = Logger.getLogger(JndiLdapLoginProvider.class.getName());
   public static final String PROVIDER_ID = "tcatLdapLoginProvider";
   private String urls;
   private String adminAccountDn;
   private String adminAccountPassword;
   private boolean useSsl;
   private boolean useTls;

   private String loginId;
   private String password;
   private String instanceId;

   private List<String> searchOUs;

   public JndiLdapLoginProvider(String urls, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls)
   {
      this.urls = urls;
      this.adminAccountDn = adminAccountDn;
      this.adminAccountPassword = adminAccountPassword;
      this.useSsl = useSsl;
      this.useTls = useTls;
   }

   public void init(String loginId, String password, String instanceId, List<String> searchOUs)
   {
      this.searchOUs = new ArrayList<>();
      if (searchOUs != null)
         this.searchOUs.addAll(searchOUs);
      this.loginId = Objects.requireNonNull(loginId);
      this.password = Objects.requireNonNull(password);
      this.instanceId = Objects.requireNonNull(instanceId);
   }

   public List<String> getSearchOUs()
   {
      return searchOUs;
   }

   @Override
   public LoginData login()
   {
      try (JndiLdapContext ctx = new JndiLdapContext(urls, adminAccountDn, adminAccountPassword, useSsl, useTls))
      {
         String filter = "(sAMAccountName={0})";
         SearchControls ctls = new SearchControls();
         ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
         ctls.setReturningAttributes(new String[0]);
         ctls.setReturningObjFlag(true);
         String dn = null;
         for (String base : searchOUs)
         {
            NamingEnumeration<SearchResult> results = ctx.getContext().search(base, filter, new String[] { loginId }, ctls);
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
                     debug.warning("Found multiple LDAP entries matching name ["+loginId+"] in OU ["+base+"]");
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

         if (ctx.authenticate(dn, password))
         {
            JndiLdapLoginData rv = new JndiLdapLoginData(ctx.getContext(), dn, PROVIDER_ID);
            return rv;
         }
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Failed to initialize LDAP authentication attempt", e);
      }
      return null;
   }
}
