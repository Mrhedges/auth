package edu.tamu.tcat.account.apacheds.ad.login;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.apacheds.LdapException;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;

/**
 * This login provider is backed by Apache Directory libraries and uses conventions
 * that exist in MS Active Directory, so may not be suitable for all LDAP uses.
 */
public class LdapLoginProvider implements LoginProvider
{
   private static final Logger debug = Logger.getLogger(LdapLoginProvider.class.getName());

   public static final String PROVIDER_ID = "ApacheDirAdLdapLoginProvider";

   private LdapHelperReader ldapHelper;
   private String username;
   private String distinguishedName;
   private String password;
   private String instanceId;

   private List<String> searchOUs;
   private String requiredGroup;

   /**
    * Initialize the login provider so {@link #login()} can execute without arguments per API.
    *
    * @param ldapHelper
    * @param username
    * @param password
    * @param instanceId
    * @param searchOUs LDAP OU identifiers to search in order. If null or empty, the ldapHelper's internally configured
    *                  default search OU is used.
    */
   public void init(LdapHelperReader ldapHelper, String username, String password, String instanceId, List<String> searchOUs)
   {
      this.searchOUs = new ArrayList<>();
      if (searchOUs != null)
         this.searchOUs.addAll(searchOUs);
      this.ldapHelper = Objects.requireNonNull(ldapHelper);
      this.username = Objects.requireNonNull(username);
      this.password = Objects.requireNonNull(password);
      this.instanceId = Objects.requireNonNull(instanceId);
   }

   /**
    * Set the name of a group of which membership is required for authentication to be successful. This is useful
    * when LDAP is configured such that accounts are members of a group for application level access.
    *
    * @param groupName
    */
   public void setRequiredGroup(String groupName)
   {
      requiredGroup = Objects.requireNonNull(groupName);
   }

   @Override
   public LoginData login() throws AccountLoginException
   {
      Objects.requireNonNull(ldapHelper, "LDAP Login Provider not initialized");
      try
      {
         for (String ou : searchOUs)
         {
            List<String> possibleIds = ldapHelper.getMatches(ou, "sAMAccountName", username);
            if (possibleIds.size() == 1)
            {
               distinguishedName = possibleIds.get(0);

               ldapHelper.checkValidPassword(distinguishedName, password);
               LdapUserData rv = new LdapUserData(ldapHelper, distinguishedName, instanceId);
               if (requiredGroup != null)
               {
                  if (!rv.groups.contains(requiredGroup))
                     throw new AccountLoginException("Authenticated account for ["+username+"] but does not have required group ["+requiredGroup+"]");
               }

               return rv;
            }

            if (possibleIds.size() > 1)
               debug.warning("Found multiple LDAP entries matching account name ["+username+"] in OU ["+ou+"]");
         }

         throw new AccountLoginException("Failed finding single match for account name ["+username+"]");
      }
      catch (LdapException e)
      {
         throw new AccountLoginException("Failed attempted login.", e);
      }
   }

   private static class LdapUserData implements LoginData
   {
      // these should be somewhere external
      /** Named key to request a value from {@link LdapUserData} type: String */
      public static final String DATA_KEY_UID = "uid";
      /** Named key to request a value from {@link LdapUserData} type: String */
      public static final String DATA_KEY_USERNAME = "username";
      /** Named key to request a value from {@link LdapUserData} type: String */
      public static final String DATA_KEY_FIRST = "first";
      /** Named key to request a value from {@link LdapUserData} type: String */
      public static final String DATA_KEY_LAST = "last";
      /** Named key to request a value from {@link LdapUserData} type: String */
      public static final String DATA_KEY_EMAIL = "email";
      /** Named key to request a value from {@link LdapUserData} type: Collection<String> */
      public static final String DATA_KEY_GROUPS = "groups";

      private String distinguishedName;
      private String firstName;
      private String lastName;
      private String displayName;
      private String email;
      private Collection<String> groups;
      private String pid;

      private LdapUserData(LdapHelperReader helper, String dn, String pid) throws LdapException
      {
         this.pid = pid;
         distinguishedName = dn;
         // display name
         displayName = String.valueOf(helper.getAttributes(dn, "displayName").stream().findFirst().orElse(null));
         // first
         firstName = String.valueOf(helper.getAttributes(dn, "givenName").stream().findFirst().orElse(null));
         // last
         lastName = String.valueOf(helper.getAttributes(dn, "sn").stream().findFirst().orElse(null));
         //email?
         email = String.valueOf(helper.getAttributes(dn, "userPrincipalName").stream().findFirst().orElse(null));
         // strip CN=*, out from distinguished names here
         groups = helper.getGroupNames(dn).stream()
               .map(name -> name.substring(name.indexOf('=') + 1, name.indexOf(',')))
               .collect(Collectors.toList());
      }

      @Override
      public String getLoginProviderId()
      {
         return pid;
      }

      @Override
      public String getLoginUserId()
      {
         return distinguishedName;
      }

      @Override
      public <T> T getData(String key, Class<T> type) throws AccountException
      {
         //HACK: these do not check requested type
         switch (key)
         {
            case DATA_KEY_UID:
               return (T)distinguishedName;
            case DATA_KEY_USERNAME:
               return (T)displayName;
            case DATA_KEY_FIRST:
               return (T)firstName;
            case DATA_KEY_LAST:
               return (T)lastName;
            case DATA_KEY_EMAIL:
               return (T)email;
            case DATA_KEY_GROUPS:
               return (T)groups;
         }
         return null;
      }
   }
}
