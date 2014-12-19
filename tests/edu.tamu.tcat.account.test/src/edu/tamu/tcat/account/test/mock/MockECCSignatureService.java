package edu.tamu.tcat.account.test.mock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.HttpHeaders;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.signature.SignatureException;
import edu.tamu.tcat.account.signature.SignatureService;
import edu.tamu.tcat.account.test.internal.Activator;
import edu.tamu.tcat.crypto.CipherException;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.EncodingException;
import edu.tamu.tcat.crypto.SignatureVerifier;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

public class MockECCSignatureService implements SignatureService<MockAccount>
{
   public static final String publicKeyString = 
         "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBrJLXdkrksgeWJsE+EEkE1f9wOIsJ"
       + "8sKMFuZs20tgTsxQgPMFsgtszI/R/IcUlOLvqHznkSYWcGAiqXhBoGvG5jMB3++d"
       + "Nlc1mxHtGLAmwaiujx5F+O/8PpCl0tyL6y1hzIQGhz2Xm1Li9AqIqJjs75S0qQim"
       + "/41CGpP3HV/05fi1oto=";
   private static final PublicKey publicKey;
   
   private static final Duration signatureDuration;

   
   static {
      try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
      {
         CryptoProvider cryptoProvider = sh.getService(CryptoProvider.class);
         publicKey = cryptoProvider.getX509KeyDecoder().decodePublicKey("ec", Base64.getDecoder().decode(publicKeyString));
      }
      catch (EncodingException e)
      {
         throw new IllegalArgumentException(e);
      }
      signatureDuration = Duration.of(2, ChronoUnit.WEEKS);
   }

   @Override
   public MockAccount getPayload(String identifier) throws SignatureException, AccountException
   {
      UUID id;
      try
      {
         id = UUID.fromString(identifier);
      }
      catch (IllegalArgumentException e)
      {
         throw new SignatureException("Identifier [" + identifier + "] is not a UUID", e);
      }
      MockAccount acct = new MockAccount();
      acct.pid = "mock.user."+id.toString();
      acct.uid = id;
      return acct;
   }

   @Override
   public Class<MockAccount> getPayloadType()
   {
      return MockAccount.class;
   }

   @Override
   public boolean mayBeSelfSigned()
   {
      return false;
   }

   //Not needed since this is not self signed but here for explanitory purposes
   @Override
   public MockAccount getSelfSigningPayload(Object result)
   {
      return (MockAccount)result;
   }

   @Override
   public String getAuthorizationScope()
   {
      return "MOCK";
   }

   @Override
   public Verifier getVerifier(MockAccount account, byte[] signature)
   {
      return new MockSignatureVerifier(account, signature);
   }

   //Not needed since this is not self signed but here for explanitory purposes
   @Override
   public SelfSignedVerifier<MockAccount> getVerifier(byte[] signature)
   {
      return new MockSelfSignedVerifier(signature);
   }

   private static void validateDateHeader(String method, Map<String, List<String>> headers)
   {
      String dateTimeString = getDateTimeHeader(headers);
      ZonedDateTime dateTime;
      if (dateTimeString != null)
      {
         try
         {
            dateTime = ZonedDateTime.parse(dateTimeString, DateTimeFormatter.RFC_1123_DATE_TIME);
         }
         catch (DateTimeParseException e)
         {
            throw new BadRequestException("Bad date format [" + dateTimeString + "]");
         }
         ZonedDateTime now = ZonedDateTime.now();
         ZonedDateTime max = now.plus(5, ChronoUnit.MINUTES);
         ZonedDateTime min = now.minus(signatureDuration);
         if (dateTime.isBefore(min) || dateTime.isAfter(max))
            throw new BadRequestException("Date [" + dateTimeString + "] out of window");
      }
      else
         dateTime = null;
      
      if (!method.equals("PUT"))
      {
         if (dateTime == null)
            throw new BadRequestException("No Date provided for request: [" + method + "]");
      }
   }
   
   private static String getDateTimeHeader(Map<String, List<String>> headers)
   {
      List<String> dateTimeHeaders = headers.get(HttpHeaders.DATE);
      if (dateTimeHeaders != null)
      {
         if (dateTimeHeaders.size() > 1)
            throw new BadRequestException("Multiple date headers are not allowed");
         else if (!dateTimeHeaders.isEmpty())
            return dateTimeHeaders.get(0);
      }
      return null;
   }
   
   private static class MockSignatureVerifier implements Verifier
   {
      private final SignatureVerifier verifier;
      
      public MockSignatureVerifier(MockAccount account, byte[] signature)
      {
         super();
         
         try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
         {
            CryptoProvider cryptoProvider = sh.getService(CryptoProvider.class);
            verifier = cryptoProvider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
         }
         catch (Exception e)
         {
            throw new InternalServerErrorException("Could not verify signature", e);
         }
      }

      @Override
      public List<String> getSignedHeaders()
      {
         return Arrays.asList(HttpHeaders.DATE);
      }

      @Override
      public void validateAdditionalHeaders(String method, Map<String, List<String>> headers)
      {
         validateDateHeader(method, headers);
      }

      @Override
      public void processSignedData(byte[] data) throws SignatureException
      {
         try
         {
            verifier.processData(data);
         }
         catch (CipherException e)
         {
            throw new SignatureException(e);
         }
      }

      @Override
      public void processSignedData(byte[] data, int offset, int bytesToRead) throws SignatureException
      {
         try
         {
            verifier.processData(data, offset, bytesToRead);
         }
         catch (CipherException e)
         {
            throw new SignatureException(e);
         }
      }

      @Override
      public boolean verify() throws SignatureException
      {
         try
         {
            return verifier.verify();
         }
         catch (CipherException e)
         {
            throw new SignatureException(e);
         }
      }
   }
   
   //Not needed since this is not self signed but here for explanitory purposes
   private static class MockSelfSignedVerifier implements SelfSignedVerifier<MockAccount>
   {
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      private final byte[] signature;
      private SignatureVerifier verifier;
      
      public MockSelfSignedVerifier(byte[] signature)
      {
         this.signature = signature;
      }
      
      @Override
      public List<String> getSignedHeaders()
      {
         return Arrays.asList(HttpHeaders.DATE);
      }

      @Override
      public void validateAdditionalHeaders(String method, Map<String, List<String>> headers)
      {
         validateDateHeader(method, headers);
      }

      @Override
      public void processSignedData(byte[] data) throws SignatureException
      {
         stream.write(data, 0, data.length);
      }

      @Override
      public void processSignedData(byte[] data, int offset, int bytesToRead) throws SignatureException
      {
         stream.write(data, offset, bytesToRead);
      }

      @Override
      public boolean verify() throws SignatureException
      {
         if (verifier == null)
            throw new IllegalStateException("No payload provided");
         
         try
         {
            verifier.processData(stream.toByteArray());
            return verifier.verify();
         }
         catch (CipherException e)
         {
            throw new SignatureException(e);
         }
      }

      @Override
      public void usePayload(MockAccount payload)
      {
         try (ServiceHelper sh = new ServiceHelper(Activator.getDefault().getContext()))
         {
            CryptoProvider cryptoProvider = sh.getService(CryptoProvider.class);
            verifier = cryptoProvider.getSignatureBuilder().buildVerifier(publicKey, DigestType.SHA512, signature);
         }
         catch (Exception e)
         {
            throw new InternalServerErrorException("Could not verify signature", e);
         }
      }
      
   }
}
