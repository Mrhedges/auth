package edu.tamu.tcat.account.apacheds;

import java.util.Collection;
import java.util.List;

public interface LdapHelperReader
{
   void checkValidUser(String user) throws LdapException;

   void checkValidUser(String ouSearchPrefix, String userDistinguishedName) throws LdapException;

   void checkValidPassword(String userDistinguishedName, String password) throws LdapException;

   // the value may need to be Object
   List<String> getMatches(String ouSearchPrefix, String attribute, String value) throws LdapException;
   
   List<String> getMatches(String ouSearchPrefix, String attribute, byte[] value) throws LdapException;

   List<String> getMembersOfGroup(String ouSearchPrefix, String groupDistinguishedName) throws LdapException;
   
   List<String> getMembersOfGroup(String groupDistinguishedName) throws LdapException;
   
   List<String> getGroups(String userDistinguishedName) throws LdapException;

   List<String> getGroups(String ouSearchPrefix, String userDistinguishedName) throws LdapException;

   List<String> getGroupsAndValidate(String userDistinguishedName, String password) throws LdapException;

   List<String> getGroupsAndValidate(String ouSearchPrefix, String userDistinguishedName, String password) throws LdapException;

   Collection<Object> getAttributes(String userDistinguishedName, String attributeId) throws LdapException;

   Collection<Object> getAttributes(String ouSearchPrefix, String userDistinguishedName, String attributeId) throws LdapException;
}
