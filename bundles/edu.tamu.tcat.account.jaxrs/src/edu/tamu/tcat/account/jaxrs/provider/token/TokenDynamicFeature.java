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
   private static final String SCOPE_ID_KEY = "scopeId";
   
   private Map<ClassAndId, TokenService<?>> tokenServices = new HashMap<>();

   public synchronized void bind(TokenService<?> svc, Map<String, Object> properties)
   {
      ClassAndId classAndId = getClassAndId(svc, properties);
      
      tokenServices.put(classAndId, svc);
   }

   private ClassAndId getClassAndId(TokenService<?> svc, Map<String, Object> properties)
   {
      Class<?> payloadType = svc.getPayloadType();
      String id = (String)properties.get(SCOPE_ID_KEY);
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
         registerSecurity(context, tokenSecured, tokenSecured.payloadType());
      }
      
      TokenProviding tokenProviding = method.getAnnotation(TokenProviding.class);
      if (tokenProviding != null)
      {
         registerProviding(context, tokenProviding, tokenProviding.payloadType());
      }
   }
   
   private <T> void registerSecurity(FeatureContext context, TokenSecured tokenSecured, Class<T> payloadType)
   {
      TokenService<T> tokenService = getService(payloadType, tokenSecured.scopeId());
      context.register(new TokenSecurityObjectFilter<T>(tokenService, tokenSecured));
   }
   
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
