package edu.tamu.tcat.account.signature;

public interface SigningAccount<PayloadType>
{
   /**
    * @return The byte representation of the account's public key.
    */
   byte[] getPublicKey();
   
   /**
    * @return The payload represented by this signing account.
    */
   PayloadType getPayload();
}
