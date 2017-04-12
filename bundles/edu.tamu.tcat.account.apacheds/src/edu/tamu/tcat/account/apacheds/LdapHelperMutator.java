package edu.tamu.tcat.account.apacheds;

import java.util.List;
import java.util.Map;

//
/**
 * This interface provides mutator access to an LDAP server
 */
public interface LdapHelperMutator
{
   void changePasswordUserPassword(String userDistinguishedName, String password) throws LdapException;
   void changePasswordUnicodePassword(String userDistinguishedName, String password) throws LdapException;
   
//TODO add group management 
   void addUserToGroup(String userDn, String groupDn) throws LdapException;
   void removeUserFromGroup(String userDn, String groupDn) throws LdapException;
   
   /**
 * DN of new user will be CN=&lt;cn&gt;,OU=&lt;ou&gt;
 * 
 * @param cn new user common name.  cannot be null or empty.  Value does not start with CN=
 * @param ou organizational unit for new user.  Value does not start with OU=
 * @param ou organizational unit for new user.  Value does not start with OU=
 * @param unicodePassword may be null.  if backing ldap uses unicode passwords, must not be null or empty
 * @param userPassword may be null.  if backing ldap uses userpassword, must not be null or empty
 * @param objectClasses classes the new user belongs to ie user, person, top, organizationalPerson.  must have ata least 1 value
 * @param instanceType 
 * @param objectCategory
 * @param attributes additional attributes to assign to user
 * @throws LdapException 
 */
   void createUser(String cn, String ou, String unicodePassword, String userPassword, List<String> objectClasses, 
		   String instanceType, String objectCategory, Map<String, String> attributes) throws LdapException;


   /**
    * Attempt to add the specified attribute value to the userDistinguishedName in ouSearchPrefix
    * */
   void addAttribute(String userDistinguishedName, String attributeId, Object value) throws LdapException;

   /**
    * Attempt to add the specified attribute value to the userDistinguishedName in ouSearchPrefix
    * */
   void modifyAttribute(String userDistinguishedName, String attributeId, Object value) throws LdapException;
   
   /**
    * Attempt to remove the specified attribute value from the userDistinguishedName in ouSearchPrefix
    */
   void removeAttribute(String userDistinguishedName, String attributeId, Object value) throws LdapException;

   /**
    * Attempt to remove all the values for the specified attribute from the userDistinguishedName in ouSearchPrefix
    */
   void removeAttribute(String userDistinguishedName, String attributeId) throws LdapException;
   
}
