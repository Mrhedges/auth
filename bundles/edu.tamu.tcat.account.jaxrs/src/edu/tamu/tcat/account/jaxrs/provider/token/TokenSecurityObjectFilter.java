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

import javax.ws.rs.BadRequestException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.token.TokenService;

public class TokenSecurityObjectFilter<PayloadType> implements ContainerRequestFilter
{
   private final TokenService<PayloadType> tokenService;
   private final TokenSecured annot;
   
   public TokenSecurityObjectFilter(TokenService<PayloadType> svc, TokenSecured annot)
   {
      this.tokenService = svc;
      this.annot = annot;
   }

   @Override
   public void filter(ContainerRequestContext requestContext) throws IOException
   {
      String tokenHeader = requestContext.getHeaderString("Token");
      if (tokenHeader == null)
         throw new BadRequestException(Response.status(Response.Status.BAD_REQUEST)
               .entity("Token not provided to service requiring token\n")
               .type(MediaType.TEXT_PLAIN)
               .build());
      try
      {
         PayloadType tokenPayload = tokenService.unpackToken(tokenHeader);
         ContextBean.from(requestContext).install(tokenService.getPayloadType()).set(annot.label(), tokenPayload);
      }
      catch (Exception e)
      {
         throw new BadRequestException(Response.status(Response.Status.BAD_REQUEST)
               .entity("Invalid token provided\n")
               .type(MediaType.TEXT_PLAIN)
               .build());
      }
   }
}
