package edu.tamu.tcat.account.apacheds;


/**
 * Provides a {@link LdapHelperReader} that has lifecycle hooks.
 * */
public interface LdapSession extends LdapHelperReader, LdapHelperMutator, AutoCloseable
{

}
