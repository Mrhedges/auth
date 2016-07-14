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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.jaxrs.internal.ClassAndId;
import edu.tamu.tcat.account.token.TokenService;

/**
 * @since 2.0
 */
@Provider
public class TokenDynamicFeature implements DynamicFeature
{
   private static final Logger debug = Logger.getLogger(TokenDynamicFeature.class.getName());

   /**
    * A configuration property defined by TokenService services bound in {@link #bind(TokenService, Map)}
    * to identify the scope for which they apply.
    */
   private static final String PROP_TOKENSVC_SCOPE_ID = "scopeId";
   /**
    * A configuration property on this service to indicate the "realm" of authentication, which is a
    * data field sent to requesting clients.
    */
   private static final String PROP_AUTH_REALM = "realm";

   /**
    * @since 2.0
    */
   public static final String HEADER_AUTHZ = "Authorization";
   /**
    * @since 2.0
    */
   public static final String HEADER_WWWAUTHN = "WWW-Authenticate";
   /**
    * @since 2.0
    */
   public static final String TOKEN_TYPE_BEARER = "Bearer";

   private Map<ClassAndId, TokenService<?>> tokenServices = new HashMap<>();

   public synchronized void bind(TokenService<?> svc, Map<String, Object> properties)
   {
      ClassAndId classAndId = getClassAndId(svc, properties);

      tokenServices.put(classAndId, svc);
   }

   private ClassAndId getClassAndId(TokenService<?> svc, Map<String, Object> properties)
   {
      Class<?> payloadType = svc.getPayloadType();
      String id = (String)properties.get(PROP_TOKENSVC_SCOPE_ID);
      if (id == null)
      {
         id = "";
      }
      ClassAndId classAndId = new ClassAndId(payloadType, id);
      return classAndId;
   }

   public synchronized void unbind(TokenService<?> svc, Map<String, Object> properties)
   {
      ClassAndId classAndId = getClassAndId(svc, properties);
      tokenServices.remove(classAndId);
   }

   void activate(Map<String, Object> properties)
   {
      try
      {
      }
      catch (Exception e)
      {
         debug.log(Level.SEVERE, "Failed activation", e);
         throw e;
      }
   }

   @Override
   public void configure(ResourceInfo resourceInfo, FeatureContext context)
   {
      Method method = resourceInfo.getResourceMethod();
      TokenSecured tokenSecured = method.getAnnotation(TokenSecured.class);
      if (tokenSecured != null)
      {
         registerSecurity(context, tokenSecured, tokenSecured.payloadType());
      }

      TokenProviding tokenProviding = method.getAnnotation(TokenProviding.class);
      if (tokenProviding != null)
      {
         registerProviding(context, tokenProviding, tokenProviding.payloadType());
      }
   }

   // separate method for generic type-safety
   private <T> void registerSecurity(FeatureContext context, TokenSecured tokenSecured, Class<T> payloadType)
   {
      TokenService<T> tokenService = getService(payloadType, tokenSecured.scopeId());
      context.register(new TokenSecurityObjectFilter<T>(tokenService, tokenSecured));
   }

   // separate method for generic type-safety
   private <T> void registerProviding(FeatureContext context, TokenProviding annot, Class<T> payloadType)
   {
      TokenService<T> tokenService = getService(payloadType, annot.scopeId());
      context.register(new TokenProvidingObjectFilter<T>(tokenService, annot));
   }

   private synchronized <T> TokenService<T> getService(Class<T> payloadType, String scopeId)
   {
      @SuppressWarnings("unchecked")
      TokenService<T> tokenService = (TokenService<T>)tokenServices.get(new ClassAndId(payloadType, scopeId));
      Objects.requireNonNull(tokenService, "Unable to access TokenService<id:"+scopeId+","+payloadType.getSimpleName()+">");
      return tokenService;
   }
}
