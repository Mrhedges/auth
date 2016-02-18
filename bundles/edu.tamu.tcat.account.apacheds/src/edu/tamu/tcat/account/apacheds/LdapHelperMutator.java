package edu.tamu.tcat.account.apacheds;

public interface LdapHelperMutator
{
   void addAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId, Object value) throws LdapException;

   void removeAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId, Object value) throws LdapException;

   void removeAttribute(String ouSearchPrefix, String userDistinguishedName, String attributeId) throws LdapException;
}
