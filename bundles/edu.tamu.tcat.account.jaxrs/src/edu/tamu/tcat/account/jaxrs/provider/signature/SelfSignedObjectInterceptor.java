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
import edu.tamu.tcat.account.jaxrs.provider.signature.SignatureStreamVerifier.SignatureStreamDelayedPublicKeyVerifier;
import edu.tamu.tcat.account.signature.SignatureService;

public class SelfSignedObjectInterceptor<PayloadType> implements ReaderInterceptor
{
   private final SignatureService<PayloadType> signatureService;
   private final SignatureSecured annot;

   public SelfSignedObjectInterceptor(SignatureService<PayloadType> signatureService, SignatureSecured annot)
   {
      this.signatureService = signatureService;
      this.annot = annot;
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
         PayloadType existingPayload = partialContext.payload;
         
         try (InputStream inputStream = context.getInputStream())
         {
            SignatureStreamDelayedPublicKeyVerifier<PayloadType> verifier = SignatureVerification.createVerifier(partialContext.selfSignedVerifier, partialContext.signPrefix.getBytes(),
                  inputStream, authorizationScope);
            context.setInputStream(verifier.getProxyStream());
            Object result = context.proceed();
            
            PayloadType payload;
            if (existingPayload != null)
               payload = existingPayload;
            else
               payload = signatureService.getSelfSigningPayload(result);
            
            verifier.checkSignature(payload);
            
            ContextBean.from(context).install(signatureService.getPayloadType()).set(annot.label(), payload);
            
            return result;
         }
      }
      catch (AccountException e)
      {
         throw new InternalServerErrorException();
      }
   }
}
