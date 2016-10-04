package edu.tamu.tcat.account.apacheds;

//
/**
 * This interface provides mutator access to an LDAP server
 */
public interface LdapHelperMutator
{
   void changePasswordUserPassword(String userDistinguishedName, String password) throws LdapException;
   void changePasswordUincodePassword(String userDistinguishedName, String password) throws LdapException;
   
   //   /**
//    * Attempt to add the specified attribute value to the userDistinguishedName in ouSearchPrefix
//    * @ param ouSearchPrefix if null ou search prefix will be extracted from userDistinguishedName
//    * */
//   void addAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId, Object value) throws LdapException;
//
//   /**
//    * Attempt to remove the specified attribute value from the userDistinguishedName in ouSearchPrefix
//    *  @ param ouSearchPrefix if null ou search prefix will be extracted from userDistinguishedName
//    */
//   void removeAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId, Object value) throws LdapException;
//
//   /**
//    * Attempt to remove all the values for the specified attribute from the userDistinguishedName in ouSearchPrefix
//    * @ param ouSearchPrefix if null ou search prefix will be extracted from userDistinguishedName
//    */
//   void removeAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId) throws LdapException;
}
