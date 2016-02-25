package edu.tamu.tcat.account.apacheds.ad.login;

import java.util.Collection;
import java.util.stream.Collectors;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.apacheds.LdapException;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;

public class LdapLoginProvider implements LoginProvider
{
   public static final String providerId = "LdapLoginProvider";
   
   private LdapHelperReader ldapHelper;
   private String distinguishedName;
   private String ouDistinguishedName;
   private String password;
   private String instanceId;

   public void init(LdapHelperReader ldapHelper, String distinguishedName, String ouDistinguishedName, String password, String instanceId)
   {
      this.ldapHelper = ldapHelper;
      this.distinguishedName = distinguishedName;
      this.ouDistinguishedName = ouDistinguishedName;
      this.password = password;
      this.instanceId = instanceId;
   }

   @Override
   public LoginData login() throws AccountLoginException
   {
      try
      {
         ldapHelper.checkValidPassword(distinguishedName, password);
         return new LdapUserData(ldapHelper, ouDistinguishedName, instanceId);
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

      private LdapUserData(LdapHelperReader helper, String ouDistinguishedName, String pid) throws LdapException
      {
         this.pid = pid;
         distinguishedName = ouDistinguishedName;
         // display name
         displayName = String.valueOf(helper.getAttributes(ouDistinguishedName, "displayName").stream().findFirst().orElse(null));
         // first
         firstName = String.valueOf(helper.getAttributes(ouDistinguishedName, "givenName").stream().findFirst().orElse(null));
         // last
         lastName = String.valueOf(helper.getAttributes(ouDistinguishedName, "sn").stream().findFirst().orElse(null));
         //email?
         email = String.valueOf(helper.getAttributes(ouDistinguishedName, "userPrincipalName").stream().findFirst().orElse(null));
         // strip CN=*, out from distinguished names here
         groups = helper.getGroupNames(ouDistinguishedName).stream().map(dn -> {
            return dn.substring(dn.indexOf('=') + 1, dn.indexOf(','));
         }).collect(Collectors.toList());
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
