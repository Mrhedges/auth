package edu.tamu.tcat.oss.account.test;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

// This is needed to do crypto stuff.
//HACK: this class is hack-ish.. should be exposed as a service
public class CryptoUtil
{
   public static boolean authenticate(String passwordRaw, String passwordHashed)
   {
      if (passwordHashed == null)
         //TODO: log: "User ["+username+"] has no stored credential"
         return false;
      PBKDF2 pbkdf2Impl = getProvider().getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.checkHash(passwordRaw, passwordHashed);
   }
   
   public static String getHash(String passwordRaw)
   {
      PBKDF2 pbkdf2Impl = getProvider().getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.deriveHash(passwordRaw);
   }
   
   private static CryptoProvider getProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
}
