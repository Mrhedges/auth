package edu.tamu.tcat.account.jndi;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import edu.tamu.tcat.account.login.LoginData;

public class JndiLdapLoginData implements LoginData
{
   private static final Logger logger = Logger.getLogger(JndiLdapLoginData.class.getName());

   /** type: String */
   public static final String DATA_KEY_DN = "dn";
   /** type: byte[] */
   public static final String DATA_KEY_GUID = "guid";
   /** type: String */
   public static final String DATA_KEY_USERNAME = "username";
   /** type: String */
   public static final String DATA_KEY_FIRST = "first";
   /** type: String */
   public static final String DATA_KEY_LAST = "last";
   /** type: String */
   public static final String DATA_KEY_EMAIL = "email";
   ///** type: Collection<String> */
   //public static final String DATA_KEY_GROUPS = "groups";

   private String distinguishedName;
   private String firstName;
   private String lastName;
   private String displayName;
   private String email;
   //private Collection<String> groups;
   private String pid;
   private String userId;
   private byte[] guid;

   public JndiLdapLoginData(LdapContext ctx, String dn, String pid) throws Exception
   {
      this.pid = pid;
      distinguishedName = dn;

      SearchControls ctls = new SearchControls();
      ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
      // looking for all of these, but some may not exist
      ctls.setReturningAttributes(new String[]{ "displayName", "name", "givenName", "sn", "mail", "objectGUID" });

      NamingEnumeration<SearchResult> results = ctx.search(dn, "(objectclass=*)", ctls);
      try
      {
         if (!results.hasMore())
            throw new IllegalStateException("Failed retrieving LDAP attributes for '"+dn+"'");
         SearchResult result = results.next();
         Attributes attribs = result.getAttributes();

         Attribute attr = attribs.get("displayName");
         if (attr == null)
         {
            attr = attribs.get("name");
            if (attr == null)
               throw new IllegalStateException("Failed looking up 'displayName'/'name' for '"+dn+"'");
         }
         displayName = (String)attr.get();

         attr = attribs.get("givenName");
         if (attr != null)
            firstName = (String)attr.get();

         attr = attribs.get("sn");
         if (attr != null)
            lastName = (String)attr.get();

         attr = attribs.get("mail");
         if (attr == null)
            throw new IllegalStateException("Failed looking up 'mail' for '"+dn+"'");
         email = (String)attr.get();

         attr = attribs.get("objectGUID");
         if (attr == null)
            throw new IllegalStateException("Failed looking up 'objectGUID' for '"+dn+"'");
         guid = (byte[])attr.get();
      }
      finally
      {
         try {
            results.close();
         } catch (Exception e) {
            logger.log(Level.WARNING, "Failed closing LDAP result", e);
         }
      }
//         // strip CN=*, out from distinguished names here
//         groups = helper.getGroupNames(dn).stream()
//               .map(name -> name.substring(name.indexOf('=') + 1, name.indexOf(',')))
//               .collect(Collectors.toList());
      // The user-id contains two parts; the first is the readable GUID, then a semicolon, then the byte string used for LDAP queries
      userId = ADDataUtils.toGuidString(guid) + ";" + ADDataUtils.toByteString(guid);
   }

   @Override
   public String getLoginProviderId()
   {
      return pid;
   }

   @Override
   public String getLoginUserId()
   {
      return userId;
   }

   @Override
   public <T> T getData(String key, Class<T> type)
   {
      //HACK: these do not check requested type
      switch (key)
      {
         case DATA_KEY_DN:
            return (T)distinguishedName;
         case DATA_KEY_GUID:
            return (T)guid;
         case DATA_KEY_USERNAME:
            return (T)displayName;
         case DATA_KEY_FIRST:
            return (T)firstName;
         case DATA_KEY_LAST:
            return (T)lastName;
         case DATA_KEY_EMAIL:
            return (T)email;
         //case DATA_KEY_GROUPS:
         //   return (T)groups;
      }
      return null;
   }
}
