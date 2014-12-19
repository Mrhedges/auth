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

public class SignatureVerification
{
   public static void requireValid(SelfSignedVerifier verifier, byte[] publicKeyBytes, byte[] message, String authorizationScope)
   {
      try
      {
         verifier.useKey(publicKeyBytes);
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
   
   public static SignatureStreamDelayedPublicKeyVerifier createVerifier(SelfSignedVerifier verifier, byte[] messageStart, InputStream input, String authorizationScope) throws IOException
   {
      return new SignatureStreamDelayedPublicKeyVerifier()
      {
         InputStreamByteArrayProxy proxy = new InputStreamByteArrayProxy(input, messageStart);
         
         @Override
         public InputStream getProxyStream()
         {
            return proxy;
         }
         
         @Override
         public void checkSignature(byte[] publicKeyBytes)
         {
            requireValid(verifier, publicKeyBytes, proxy.getBytes(), authorizationScope);
         }
      };
   }

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
