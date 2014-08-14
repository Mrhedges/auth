package edu.tamu.tcat.account.jaxrs.provider.token;

import java.lang.reflect.Method;
import java.util.Objects;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.token.TokenService;

@Provider
public class TokenDynamicFeature<PayloadType> implements DynamicFeature
{
   private TokenService<?> tokenService;

   //TODO: allow binding to multiple services defined in the app
   // Can't trust the generic type, so check later after accepting the bind
   public void bind(TokenService<?> svc)
   {
      this.tokenService = svc;
   }
   
   public void activate()
   {
      //Objects.requireNonNull(tokenService);
   }
   
   @Override
   public void configure(ResourceInfo resourceInfo, FeatureContext context)
   {
      Method method = resourceInfo.getResourceMethod();
      TokenSecured tokenSecured = method.getAnnotation(TokenSecured.class);
      if (tokenSecured != null)
      {
         Class<?> payloadType = tokenSecured.payloadType();
         // Only register if the annotation payload type matches the provided service
         if (Objects.equals(tokenService.getPayloadType(), payloadType))
         {
            TokenService<PayloadType> typed = (TokenService)tokenService;
            context.register(new TokenSecurityObjectFilter<PayloadType>(typed));
         }
      }
      
      TokenProviding tokenProviding = method.getAnnotation(TokenProviding.class);
      if (tokenProviding != null)
      {
         Class<?> payloadType = tokenProviding.payloadType();
         // Only register if the annotation payload type matches the provided service
         if (Objects.equals(tokenService.getPayloadType(), payloadType))
         {
            TokenService<PayloadType> typed = (TokenService)tokenService;
            context.register(new TokenProvidingObjectFilter<PayloadType>(typed));
         }
      }
   }
}
