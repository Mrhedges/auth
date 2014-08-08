package edu.tamu.tcat.account.db.spi;

import javax.security.auth.callback.Callback;

import edu.tamu.tcat.crypto.CryptoProvider;

/**
 * A {@link Callback} that allows a {@link CryptoProvider} service to be passed
 * into the {@link DatabaseLoginModule}.
 * <p>
 * This is needed because login modules are constructed reflectively and treated
 * only using their base API. This prevents injects from system components. Also,
 * a login module which looks up services from some service provider would couple
 * the login module to that system and make testing and mocking difficult, which is
 * not desirable. Therefore, a callback is used to allow the caller to knowingly
 * inject a {@link CryptoProvider} into the login module instance.
 * <p>
 * Note that instances are not {@link java.io.Serializable}.
 */
public class CryptoProviderCallback implements Callback
{
   private transient CryptoProvider provider;
   
   public CryptoProvider getProvider()
   {
      return provider;
   }
   
   public void setProvider(CryptoProvider provider)
   {
      this.provider = provider;
   }
}
