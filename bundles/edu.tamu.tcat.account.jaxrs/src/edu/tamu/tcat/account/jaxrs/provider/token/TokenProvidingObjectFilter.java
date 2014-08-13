package edu.tamu.tcat.account.jaxrs.provider.token;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.TokenService.TokenData;

public class TokenProvidingObjectFilter<PayloadType> implements ContainerRequestFilter, ContainerResponseFilter
{
   private static final Logger debug = Logger.getLogger(TokenProvidingObjectFilter.class.getName());
   private final TokenService<PayloadType> tokenService;
   
   public TokenProvidingObjectFilter(TokenService<PayloadType> tokenService)
   {
      this.tokenService = tokenService;
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
      try
      {
         PayloadType payload = ContextBean.getValue(requestContext, tokenService.getPayloadType());
         if (payload != null)
         {
            TokenData<PayloadType> data = tokenService.createTokenData(payload, 2 * 7, TimeUnit.DAYS);
            String token = data.getToken();
            responseContext.getHeaders().add("Token", token);
         }
      }
      catch (Exception e)
      {
         debug.log(Level.WARNING, "Could not create token", e);
         throw new InternalServerErrorException("Could not create token");
      }
   }
}