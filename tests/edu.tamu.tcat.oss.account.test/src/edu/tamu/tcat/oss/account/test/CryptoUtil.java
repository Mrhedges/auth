package edu.tamu.tcat.oss.account.test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

// This is needed to do crypto stuff.
//TODO: get apache.commons 1.5 or later into the target platform to fix Base64 issues
//TODO: how to properly get bouncycastle library into SDA?
public class CryptoUtil
{
   public static boolean authenticate(String passwordRaw, String passwordHashed)
   {
      if (passwordHashed == null)
         //TODO: log: "User ["+username+"] has no stored credential"
         return false;
      PBKDF2 pbkdf2Impl = new PBKDF2(DigestType.SHA1);
      return pbkdf2Impl.checkHash(passwordRaw, passwordHashed);
   }
   
   public static String getHash(String passwordRaw)
   {
      PBKDF2 pbkdf2Impl = new PBKDF2(DigestType.SHA1);
      return pbkdf2Impl.deriveHash(passwordRaw);
   }
   
   enum DigestType {
      SHA1,
//      SHA224,
//      SHA256,
//      SHA384,
//      SHA512,
      ;
   }
   
   static class DigestTypeMap {
      
      public static Digest getDigest(DigestType type)
      {
         Objects.requireNonNull(type);
         switch (type)
         {
            case SHA1:
               return new SHA1Digest();
//            case SHA224:
//               return new SHA224Digest();
//            case SHA256:
//               return new SHA256Digest();
//            case SHA384:
//               return new SHA384Digest();
//            case SHA512:
//               return new SHA512Digest();
            default:
               throw new IllegalArgumentException();
         }
      }
   }
   
   static class PBKDF2
   {
      protected final DigestType digest;
      private final Digest bouncyDigest;
      
      public PBKDF2(DigestType digest)
      {
         this.digest = digest;
         bouncyDigest = DigestTypeMap.getDigest(digest);
      }
      
      public String deriveHash(String password)
      {
         byte[] salt = new byte[16];
         new SecureRandom().nextBytes(salt);

         return deriveHash(passwordToBytes(password), 10_000, salt);
      }
      
      public boolean checkHash(String password, String hash)
      {
         return checkHash(passwordToBytes(password), hash);
      }
      
      public boolean checkHash(byte[] password, String hash)
      {
         //Decoding and sanity checks
         String[] components = hash.split("\\$");
         if (components.length != 5 || components[0].length() != 0)
            return false;
         
         String hashType = components[1];
         String roundsStr = components[2];
         //NOTE: revert '.' to '+', which was previously converted to avoid issues with URL encoding of the derived hash (converting '+' to "%2B")
         String saltStr = components[3].replace('.', '+');
         String outputStr = components[4].replace('.', '+');
         
         DigestType dgst;
         if (!hashType.startsWith("pbkdf2"))
            return false;
         if (hashType.equals("pbkdf2"))
            dgst = DigestType.SHA1;
         else if (hashType.startsWith("pbkdf2-"))
         {
            String type = hashType.substring(7).toUpperCase();
            try
            {
               dgst = DigestType.valueOf(type);
            }
            catch (Exception e)
            {
               return false;
            }
         }
         else
            return false;
         
         int rounds;
         try
         {
            rounds = Integer.parseInt(roundsStr);
         }
         catch (NumberFormatException e)
         {
            return false;
         }
         
         return checkHash(password, saltStr, outputStr, dgst, rounds);
      }
      
      public byte[] deriveKey(byte[] password, byte[] salt, int rounds, int keySizeInBytes)
      {
         PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(bouncyDigest);
         generator.init(password, salt, rounds);
         KeyParameter keyParameter = (KeyParameter)generator.generateDerivedMacParameters(keySizeInBytes * 8);
         return keyParameter.getKey();
      }
      
      protected String deriveHash(byte[] password, int rounds, byte[] salt)
      {
         int outputSize = bouncyDigest.getDigestSize();
         
         String hashType;
         if (digest == DigestType.SHA1)
            hashType = "pbkdf2";
         else
            hashType = "pbkdf2-" + digest.name().toLowerCase();
         byte[] output = deriveKey(password, salt, rounds, outputSize);
         // Use "$" as separator between entries in the field. Returning a single string is helpful to store as a single
         // value e.g. in a database table, but multiple pieces of information are required. The separator is used elsewhere, so is
         // just as good as another field separator.
         //NOTE: convert '+' to '.' to avoid issues with URL encoding of the derived hash (converting '+' to "%2B")
         return "$" + hashType + "$" + rounds + "$" + Base64.encodeBase64String(salt).replace('+', '.') + "$" + Base64.encodeBase64String(output).replace('+', '.');
      }

      protected boolean checkHash(byte[] password, String saltStr, String outputStr, DigestType dgst, int rounds)
      {
         if (!Base64.isBase64(saltStr) || !Base64.isBase64(outputStr))
            return false;
         
         byte[] salt = Base64.decodeBase64(saltStr);
         byte[] output = Base64.decodeBase64(outputStr);
         
         int outputSize = DigestTypeMap.getDigest(digest).getDigestSize();
         if (output.length != outputSize)
            return false;
         
         PBKDF2 pbkdf2 = new PBKDF2(dgst);
         byte[] candidate = pbkdf2.deriveKey(password, salt, rounds, outputSize);
         return Arrays.equals(candidate, output);
      }
      
      private byte[] passwordToBytes(String password)
      {
         return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray());
      }
   }
}
