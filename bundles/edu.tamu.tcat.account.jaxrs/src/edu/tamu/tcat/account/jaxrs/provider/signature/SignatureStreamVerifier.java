package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.InputStream;

public interface SignatureStreamVerifier
{
   InputStream getProxyStream();
   
   interface SignatureStreamDelayedPublicKeyVerifier extends SignatureStreamVerifier
   {
      void checkSignature(byte[] publicKeyBytes);
   }
   
   interface SignatureStreamWithPublicKeyVerifier extends SignatureStreamVerifier
   {
      void checkSignature();
   }
}
