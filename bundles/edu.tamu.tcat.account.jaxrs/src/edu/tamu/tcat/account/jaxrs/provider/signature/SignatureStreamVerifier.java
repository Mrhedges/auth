package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.InputStream;

public interface SignatureStreamVerifier
{
   InputStream getProxyStream();
   
   interface SignatureStreamDelayedPublicKeyVerifier<PayloadType> extends SignatureStreamVerifier
   {
      void checkSignature(PayloadType payload);
   }
   
   interface SignatureStreamWithPublicKeyVerifier extends SignatureStreamVerifier
   {
      void checkSignature();
   }
}
