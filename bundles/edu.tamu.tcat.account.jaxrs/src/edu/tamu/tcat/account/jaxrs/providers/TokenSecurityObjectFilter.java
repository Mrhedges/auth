package edu.tamu.tcat.account.jaxrs.providers;

import java.io.IOException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.token.TokenService;

public class TokenSecurityObjectFilter<PayloadType> implements ContainerRequestFilter
{
   private final TokenService<PayloadType> tokenService;
   
   public TokenSecurityObjectFilter(TokenService<PayloadType> svc)
   {
      this.tokenService = svc;
   }

   @Override
   public void filter(ContainerRequestContext requestContext) throws IOException
   {
//      try
//      {
         String tokenHeader = requestContext.getHeaderString("Token");
//         if (tokenHeader == null)
//            throw new BadEPSSRequestException("Token not provided to service requiring token\n");
         try
         {
            PayloadType tokenPayload = tokenService.unpackToken(tokenHeader);
            ContextBean.from(requestContext).install(tokenService.getPayloadType()).set(tokenPayload);
         }
         catch (Exception e)
         {
//            //The token was invalid.
//            throw new BadEPSSRequestException("Invalid token provided\n");
         }
//      }
//      catch (BadEPSSRequestException e)
//      {
//         throw BadEPSSRequestExceptionMapper.createException(e);
//      }
   }
}
