package edu.tamu.tcat.account.jaxrs.provider.signature;

import edu.tamu.tcat.account.signature.SignatureService.Verifier;
import edu.tamu.tcat.account.signature.SignatureService.SelfSignedVerifier;

/**
 * Container object used by Object Filters and Object Interceptors for internal communication
 * @param <PayloadType> The type of the payload object.
 */
class PartialContext<PayloadType>
{
   public String accountIdentifier;
   public Verifier verifier;
   public SelfSignedVerifier<PayloadType> selfSignedVerifier;
   public PayloadType payload;
   public byte[] signature;
   public String signPrefix;
   
   public PartialContext(String accountIdentifier, byte[] signature)
   {
      this.accountIdentifier = accountIdentifier;
      this.signature = signature;
   }
}