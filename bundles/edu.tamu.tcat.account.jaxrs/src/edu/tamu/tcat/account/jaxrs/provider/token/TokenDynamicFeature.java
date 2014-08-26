/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
