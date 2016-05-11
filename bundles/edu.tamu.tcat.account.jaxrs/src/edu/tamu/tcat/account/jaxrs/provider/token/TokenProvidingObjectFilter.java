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
import java.time.format.DateTimeFormatter;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.TokenService.TokenData;

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
         if (payload != null)
         {
            TokenData<PayloadType> data = tokenService.createTokenData(payload);
            String token = data.getToken();
            String expireStr = DateTimeFormatter.RFC_1123_DATE_TIME.format(data.getExpiration());
            responseContext.getHeaders().add("Token", token + ";expires=" + expireStr);
         }
         else if (annot.strict())
         {
            throw new IllegalStateException("TokenProviding in strict mode but no payload set");
         }
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Could not create token", e);
         throw new InternalServerErrorException("Could not create token");
      }
   }
}
