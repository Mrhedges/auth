package edu.tamu.tcat.account.jaas;

import java.security.Principal;

import javax.security.auth.spi.LoginModule;

import edu.tamu.tcat.account.login.LoginData;

/**
 * A JAAS {@link Principal} that provides access to a {@link LoginData}, allowing the
 * {@link LoginModule} to construct one from its accessible data.
 * <p>
 * If one of these is needed an a <tt>LoginModule</tt> does not provide one,
 * the caller will need to construct a <tt>LoginData</tt> from
 * the <tt>Principal</tt>s known to be provided by that <tt>LoginModule</tt>.
 */
public interface LoginDataPrincipal extends Principal
{
   LoginData getLoginData();
}
