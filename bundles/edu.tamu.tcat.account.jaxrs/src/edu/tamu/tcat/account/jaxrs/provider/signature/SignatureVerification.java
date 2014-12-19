package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.IOException;
import java.io.InputStream;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import edu.tamu.tcat.account.jaxrs.provider.signature.SignatureStreamVerifier.SignatureStreamDelayedPublicKeyVerifier;
import edu.tamu.tcat.account.jaxrs.provider.signature.SignatureStreamVerifier.SignatureStreamWithPublicKeyVerifier;
import edu.tamu.tcat.account.signature.SignatureService.SelfSignedVerifier;
import edu.tamu.tcat.account.signature.SignatureService.Verifier;

/**
 * Helper class for verifying signatures
 */
public class SignatureVerification
{
   /**
    * Method to check a signature and return if valid, throw if not
    * @param verifier The verifier to use
    * @param payload The payload object which is used by the verifier
    * @param message The message on which to check the signature
    * @param authorizationScope The scope of the authorization (used for HTTP response in case of failure)
    */
   public static <T> void requireValid(SelfSignedVerifier<T> verifier, T payload, byte[] message, String authorizationScope)
   {
      try
      {
         verifier.usePayload(payload);
         verifier.processSignedData(message);
         requireVerification(verifier);
      }
      catch (Exception e)
      {
         throw new InternalServerErrorException("Could not verify signature", e);
      }
   }
   
   private static void requireVerification(Verifier verifier)
   {
      if (!verifier.verify())
         throw new BadRequestException(Response.status(Response.Status.BAD_REQUEST)
               .entity("Failed integrity")
               .type(MediaType.TEXT_PLAIN)
               .build());
   }
   
   /**
    * Method to fetch a {@link SignatureStreamDelayedPublicKeyVerifier} to check a message's signature
    * @param verifier The verifier to use
    * @param messageStart The start of the message on which to check the signature
    * @param input An {@link InputStream} through which the rest of the message will be read
    * @param authorizationScope The scope of the authorization (used for HTTP response in case of failure)
    */
   public static <T> SignatureStreamDelayedPublicKeyVerifier<T> createVerifier(SelfSignedVerifier<T> verifier, byte[] messageStart, InputStream input, String authorizationScope) throws IOException
   {
      return new SignatureStreamDelayedPublicKeyVerifier<T>()
      {
         InputStreamByteArrayProxy proxy = new InputStreamByteArrayProxy(input, messageStart);
         
         @Override
         public InputStream getProxyStream()
         {
            return proxy;
         }
         
         @Override
         public void checkSignature(T payload)
         {
            requireValid(verifier, payload, proxy.getBytes(), authorizationScope);
         }
      };
   }

   /**
    * Method to fetch a {@link SignatureStreamWithPublicKeyVerifier} to check a message's signature
    * @param verifier The verifier to use
    * @param messageStart The start of the message on which to check the signature
    * @param input An {@link InputStream} through which the rest of the message will be read
    * @param authorizationScope The scope of the authorization (used for HTTP response in case of failure)
    */
   public static SignatureStreamWithPublicKeyVerifier createVerifier(Verifier verifier, byte[] messageStart, InputStream input, String authorizationScope) throws IOException
   {
      try
      {
         verifier.processSignedData(messageStart);
      }
      catch (Exception e)
      {
         throw new InternalServerErrorException("Could not verify signature", e);
      }
      final InputStream proxy = new InputStreamSignatureVerifierProxy(input, verifier);
      return new SignatureStreamWithPublicKeyVerifier()
      {
         @Override
         public InputStream getProxyStream()
         {
            return proxy;
         }
         
         @Override
         public void checkSignature()
         {
            requireVerification(verifier);
         }
      };
   }
}
