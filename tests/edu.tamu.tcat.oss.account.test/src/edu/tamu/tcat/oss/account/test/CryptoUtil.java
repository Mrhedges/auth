package edu.tamu.tcat.oss.account.test;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

// This is needed to do crypto stuff.
//HACK: this class is hack-ish.. should be exposed as a service
/** @deprecated These utilities should be exposed more locally to where they are needed */
@Deprecated
public final class CryptoUtil
{
   public static boolean authenticate(String passwordRaw, String passwordHashed)
   {
      return authenticate(getProvider(), passwordRaw, passwordHashed);
   }
   
   public static boolean authenticate(CryptoProvider cp, String passwordRaw, String passwordHashed)
   {
      if (passwordHashed == null)
         //TODO: log: "User ["+username+"] has no stored credential"
         return false;
      PBKDF2 pbkdf2Impl = cp.getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.checkHash(passwordRaw, passwordHashed);
   }
   
   public static String getHash(String passwordRaw)
   {
      return getHash(getProvider(), passwordRaw);
   }
   
   public static String getHash(CryptoProvider cp, String passwordRaw)
   {
      PBKDF2 pbkdf2Impl = cp.getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.deriveHash(passwordRaw);
   }
   
   public static CryptoProvider getProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
}
