package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.IOException;
import java.io.InputStream;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.ext.ReaderInterceptor;
import javax.ws.rs.ext.ReaderInterceptorContext;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.SignatureSecured;
import edu.tamu.tcat.account.jaxrs.provider.signature.SignatureStreamVerifier.SignatureStreamWithPublicKeyVerifier;
import edu.tamu.tcat.account.signature.SignatureService;

public class SignedObjectInterceptor<PayloadType> implements ReaderInterceptor
{
   private final SignatureService<PayloadType> signatureService;
   private final SignatureSecured signatureSecured;

   public SignedObjectInterceptor(SignatureService<PayloadType> signatureService, SignatureSecured signatureSecured)
   {
      this.signatureService = signatureService;
      this.signatureSecured = signatureSecured;
   }

   @Override
   public Object aroundReadFrom(ReaderInterceptorContext context) throws IOException, WebApplicationException
   {
      String authorizationScope = signatureService.getAuthorizationScope();
      try
      {
         @SuppressWarnings("unchecked")
         PartialContext<PayloadType> partialContext = ContextBean.from(context).install(PartialContext.class).get("");
         if (partialContext == null)
            throw new NotAuthorizedException(authorizationScope);
         PayloadType payload = partialContext.payload;
         if (payload == null)
            throw new NotAuthorizedException(authorizationScope);
         
         try (InputStream inputStream = context.getInputStream())
         {
            SignatureStreamWithPublicKeyVerifier verifier = SignatureVerification.createVerifier(partialContext.verifier, partialContext.signPrefix.getBytes(),
                  inputStream, authorizationScope);
            context.setInputStream(verifier.getProxyStream());
            Object result = context.proceed();
            
            verifier.checkSignature();
            
            ContextBean.from(context).install(signatureService.getPayloadType()).set(signatureSecured.label(), payload);
            
            return result;
         }
      }
      catch (AccountException e)
      {
         throw new InternalServerErrorException();
      }
   }

}
