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

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.token.TokenService;

@Provider
public class TokenDynamicFeature implements DynamicFeature
{
   private Map<ClassAndId, TokenService<?>> tokenServices = new HashMap<>();

   public void bind(TokenService<?> svc, Map<String, Object> properties)
   {
      Class<?> payloadType = svc.getPayloadType();
      Object idObj = properties.get("tokenId");
      String id = "";
      if (idObj != null && idObj instanceof String)
      {
         id = (String)idObj;
      }
      
      tokenServices.put(new ClassAndId(payloadType, id), svc);
   }
   
   public void activate()
   {
   }
   
   @Override
   public void configure(ResourceInfo resourceInfo, FeatureContext context)
   {
      Method method = resourceInfo.getResourceMethod();
      TokenSecured tokenSecured = method.getAnnotation(TokenSecured.class);
      if (tokenSecured != null)
      {
         Class<?> payloadType = tokenSecured.payloadType();
         String tokenId = tokenSecured.tokenId();
         
         registerSecurity(payloadType, tokenId, context);
      }
      
      TokenProviding tokenProviding = method.getAnnotation(TokenProviding.class);
      if (tokenProviding != null)
      {
         Class<?> payloadType = tokenProviding.payloadType();
         String tokenId = tokenProviding.tokenId();
         
         registerProviding(payloadType, tokenId, context);
      }
   }
   
   private <T> void registerSecurity(Class<T> payloadType, String tokenId, FeatureContext context)
   {
      @SuppressWarnings("unchecked")
      TokenService<T> tokenService = (TokenService<T>)tokenServices.get(new ClassAndId(payloadType, tokenId));
      context.register(new TokenSecurityObjectFilter<T>(tokenService));
   }
   
   private <T> void registerProviding(Class<T> payloadType, String tokenId, FeatureContext context)
   {
      @SuppressWarnings("unchecked")
      TokenService<T> tokenService = (TokenService<T>)tokenServices.get(new ClassAndId(payloadType, tokenId));
      context.register(new TokenProvidingObjectFilter<T>(tokenService));
   }
   
   private static class ClassAndId
   {
      public final Class<?> cls;
      public final String id;
      public ClassAndId(Class<?> cls, String id)
      {
         this.cls = cls;
         this.id = id;
      }
      @Override
      public int hashCode()
      {
         final int prime = 31;
         int result = 1;
         result = prime * result + ((cls == null) ? 0 : cls.hashCode());
         result = prime * result + ((id == null) ? 0 : id.hashCode());
         return result;
      }
      @Override
      public boolean equals(Object obj)
      {
         if (this == obj)
            return true;
         if (obj == null)
            return false;
         if (getClass() != obj.getClass())
            return false;
         ClassAndId other = (ClassAndId)obj;
         if (cls == null)
         {
            if (other.cls != null)
               return false;
         }
         else if (!cls.equals(other.cls))
            return false;
         if (id == null)
         {
            if (other.id != null)
               return false;
         }
         else if (!id.equals(other.id))
            return false;
         return true;
      }
   }
}
