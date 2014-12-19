package edu.tamu.tcat.account.jaxrs.provider.signature;

import edu.tamu.tcat.account.signature.SignatureService.SelfSignedVerifier;
import edu.tamu.tcat.account.signature.SignatureService.Verifier;
import edu.tamu.tcat.account.signature.SigningAccount;

class PartialContext
{
   public SigningAccount<?> signingAccount;
   public String accountIdentifier;
   public Verifier verifier;
   public SelfSignedVerifier selfSignedVerifier;
   public byte[] signature;
   public String signPrefix;
   
   public PartialContext(String accountIdentifier, byte[] signature)
   {
      this.accountIdentifier = accountIdentifier;
      this.signature = signature;
   }
}