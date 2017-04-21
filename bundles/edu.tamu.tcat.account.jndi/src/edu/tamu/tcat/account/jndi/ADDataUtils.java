package edu.tamu.tcat.account.jndi;

import java.util.Arrays;
import java.util.List;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

/**
 * Helper class to facilitate conversion of MS AD/LDS data value types, such as for "objectGUID"
 * and passwords.
 */
public class ADDataUtils
{
   /**
    * Converts a GUID byte[] as retrieved from MS AD/LDS to a "readable" GUID value
    * of the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    */
   public static String toGuidString(byte[] objectGUID)
   {
      StringBuilder uuidStr = new StringBuilder();

      int[] positions = {3,2,1,0, -1, 5,4, -1, 7,6, -1, 8,9, -1, 10,11,12,13,14,15};

      for (int pos : positions)
      {
         if (pos < 0)
         {
            uuidStr.append('-');
         }
         else
         {
            int b = (int)objectGUID[pos] & 0xFF;
            if (b <= 0xF)
               uuidStr.append('0');
            uuidStr.append(Integer.toHexString(b));
         }
      }

      return uuidStr.toString();
   }

   /**
    * Converts a GUID byte[] as retrieved from MS AD/LDS to a JNDI name of the format
    * "<GUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>". This may be used for certain queries
    * as a DN to bypass a GUID to DN lookup.
    */
   public static String toGuidBindingString(byte[] objectGUID)
   {
      return "<GUID=" + toGuidString(objectGUID) + ">";
   }

   /**
    * Converts a GUID byte[] as retrieved from MS AD/LDS to a query key
    * of the format having with 16 "\xx" hex segments.
    * This value may be used in an LDAP query such as:
    * (objectGUID=\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01)
    */
   public static String toByteString(byte[] objectGUID)
   {
      StringBuilder out = new StringBuilder();

      for (byte b : objectGUID)
      {
         out.append('\\');
         int v = (int)b & 0xFF;
         if (v <= 0xF)
            out.append('0');
         out.append(Integer.toHexString(v));
      }

      return out.toString();
   }

   public static byte[] encodeUnicodePassword(String password)
   {
      String quotedPassword = "\"" + password + "\"";
      char unicodePwd[] = quotedPassword.toCharArray();
      byte pwdArray[] = new byte[unicodePwd.length * 2];
      for (int i = 0; i < unicodePwd.length; i++)
      {
          pwdArray[i * 2 + 1] = (byte)(unicodePwd[i] >>> 8);
          pwdArray[i * 2 + 0] = (byte)(unicodePwd[i] & 0xff);
      }
      return pwdArray;
   }

   /**
    * Build an {@link Attributes} that can be used to create a new identity LDAP entry.
    * These attributes can be passed to a {@code DirContext.createSubcontext} call.
    *
    * @param loginId The "username", like "john.doe"
    * @param password The plaintext password
    * @param displayName The (abbreviated) common name or CN, like "John Doe"
    * @param distinguishedName The full DN for the new entry
    * @param email
    * @param objectCategory The category of the object, specific to the local LDAP instance, such as
    *       "CN=Person,CN=Schema,CN=Configuration,CN={ instance-guid }"
    */
   public static Attributes buildCreateEntryAttributes(String loginId,
                                                       String password,
                                                       String displayName,
                                                       String distinguishedName,
                                                       String email,
                                                       String objectCategory)
   {
      //NOTE: some of these are specific to our LDS installation; not sure what needs to change if our LDAP system is altered
      List<String> objClasses = Arrays.asList("organizationalPerson", "person", "top", "user");
      String instanceType="4";

      BasicAttributes attributes = new BasicAttributes();
      attributes.put("cn", displayName);
      Attribute clsses = new BasicAttribute("objectClass");
      for (String cls: objClasses)
         clsses.add(cls);
      attributes.put(clsses);
      attributes.put("instanceType", instanceType);
      attributes.put("objectCategory",objectCategory);
      attributes.put("distinguishedName", displayName);
      attributes.put("msDS-UserAccountDisabled", "FALSE");
      attributes.put("msDS-UserDontExpirePassword", "TRUE");
      attributes.put("name", displayName);
      attributes.put("sAMAccountName", loginId);
      attributes.put("userpassword", password);
      attributes.put("mail", email);

      return attributes;
   }
}
