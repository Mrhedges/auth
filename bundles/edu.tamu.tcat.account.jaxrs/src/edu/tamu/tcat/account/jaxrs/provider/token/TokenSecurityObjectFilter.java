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
import java.util.List;
import java.util.stream.Collectors;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;
import edu.tamu.tcat.account.token.TokenService;

/**
 * A request filter that implements the Authorization bearer token usage defined by
 * {@link http://tools.ietf.org/html/rfc6750#section-2}.
 *
 * @param <PayloadType>
 * @see TokenSecured
 */
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
      MultivaluedMap<String, String> map = requestContext.getHeaders();
      List<String> authKeys = map.keySet().stream()
         .filter(s -> s.equalsIgnoreCase(TokenDynamicFeature.HEADER_AUTHZ))
         .collect(Collectors.toList());

      Response.ResponseBuilder badRequest = Response.status(Response.Status.BAD_REQUEST)
         //TODO: if "realm" config provided, add it here
         .header(TokenDynamicFeature.HEADER_WWWAUTHN, "Bearer")
         .type(MediaType.TEXT_PLAIN);

      if (authKeys.isEmpty() && annot.required())
         throw new BadRequestException(badRequest.entity("Token not provided to service requiring token").build());

      // request context container is required regardless of whether the token payload is present or not:
      // we set up this container here and populate it later if we have a token.
      ContextBean.Installer installer = ContextBean.from(requestContext);
      ContextBean.Container<PayloadType> container = installer.install(tokenService.getPayloadType());

      if (!authKeys.isEmpty())
      {
         String header = map.getFirst(authKeys.get(0));
         if (header == null || header.length() < 8 ||
             // Get the substring of the token instead of toLowerCase on the whole token for a minor optimization
             !header.substring(0,7).toLowerCase().equals(TokenDynamicFeature.TOKEN_TYPE_BEARER.toLowerCase()+" "))
            throw new BadRequestException(badRequest.entity("No Bearer token provided").build());

         // if the client provides a token, it should be valid
         // see documentation on {@link TokenSecured} for more details.
         try
         {
            String token = header.substring(7);
            PayloadType tokenPayload = tokenService.unpackToken(token);
            container.set(annot.label(), tokenPayload);
         }
         catch (Exception e)
         {
            throw new BadRequestException(badRequest.entity("Invalid token provided").build());
         }
      }
   }
}
