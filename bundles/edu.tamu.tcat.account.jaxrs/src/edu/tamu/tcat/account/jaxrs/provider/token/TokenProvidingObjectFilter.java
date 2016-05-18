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

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.MediaType;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.TokenService.TokenData;

/**
 * A response filter that implements the Authorization endpoint defined by {@link http://tools.ietf.org/html/rfc6749#section-3.1}
 * and using the grant mechanism of {@link http://tools.ietf.org/html/rfc6749#section-4.3}.
 * <p>
 * For this implementation, the return type of the (java) method must be Map&lt;String,Object&gt; so the annotation processor
 * can inject the additional keys into the map before its serialization to JSON. This is used to follow the OAuth2 spec
 * such that a response to the HTTP request contains the auth information and not a header. See
 * {@link http://tools.ietf.org/html/rfc6749#section-5}
 * <p>
 * The HTTP Method should be GET to support the spec requirement in section 3.1.
 *
 * @param <PayloadType>
 * @see TokenProviding
 */
public class TokenProvidingObjectFilter<PayloadType> implements ContainerRequestFilter, ContainerResponseFilter
{
   private static final Logger debug = Logger.getLogger(TokenProvidingObjectFilter.class.getName());
   private final TokenService<PayloadType> tokenService;
   private final TokenProviding annot;

   public TokenProvidingObjectFilter(TokenService<PayloadType> tokenService, TokenProviding annot)
   {
      this.tokenService = tokenService;
      this.annot = annot;
   }

   @Override
   public void filter(ContainerRequestContext requestContext) throws IOException
   {
      try
      {
         ContextBean.from(requestContext).install(tokenService.getPayloadType());
      }
      catch (AccountException e)
      {
         debug.log(Level.WARNING, "Could not install context bean", e);
         throw new InternalServerErrorException("Could not initialize token provider");
      }
   }

   @Override
   public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException
   {
      switch (responseContext.getStatusInfo().getFamily())
      {
         case CLIENT_ERROR:
         case SERVER_ERROR:
            return;
         default:
            break;
      }

      try
      {
         PayloadType payload = ContextBean.getValue(requestContext, tokenService.getPayloadType(), annot.label());
         if (payload == null)
            throw new IllegalStateException("TokenProviding has no payload set in context");

         TokenData<PayloadType> data = tokenService.createTokenData(payload);
         String token = data.getToken();
         Duration dur = Duration.between(LocalDateTime.now(), data.getExpiration());
         String expireStr = DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(data.getExpiration());
         // Per the spec, the "expires_in" property is seconds from response generation; see http://tools.ietf.org/html/rfc6749#section-4.2.2
         String expiresIn = String.valueOf(dur.getSeconds());

         if (!responseContext.getMediaType().toString().equals(MediaType.APPLICATION_JSON))
            throw new IllegalStateException("TokenProviding must apply to MediaType of " + MediaType.APPLICATION_JSON +" but is " + responseContext.getMediaType());

         Object entity = responseContext.getEntity();
         if (entity instanceof Map)
         {
            try
            {
               // See http://tools.ietf.org/html/rfc6750#section-4
               // and http://tools.ietf.org/html/rfc6749#section-4.2.2
               Map<String, Object> entityMap = (Map)entity;
               entityMap.put("access_token", token);
               entityMap.put("token_type", TokenDynamicFeature.TOKEN_TYPE_BEARER);
               entityMap.put("expires_in", expiresIn);
               entityMap.put("expiration", expireStr);
               return;
            }
            catch (Exception e)
            {
               throw new IllegalStateException("Failed mutating returned Map with token data");
            }
         }

         throw new IllegalStateException("TokenProviding must apply to return value of java.util.Map");
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Could not provide token", e);
         throw new InternalServerErrorException("Could not provide token", e);
      }
   }
}
