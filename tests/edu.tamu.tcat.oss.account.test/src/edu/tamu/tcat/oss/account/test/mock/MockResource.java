package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import javax.ws.rs.BeanParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenProviding;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;

@Path("/mock")
public class MockResource
{
   @POST
   @TokenSecured(payloadType=UUID.class)
   public String doPost(@BeanParam ContextBean bean) throws AccountException
   {
      System.out.println("post");
      UUID uuid = bean.get(UUID.class);
      return "posted: " + uuid;
   }
   
   @GET
   @Path ("/reAuthenticate")
   @Produces (MediaType.APPLICATION_JSON)
   @TokenProviding(payloadType=UUID.class)
   public String reAuthenticate(@BeanParam ContextBean bean) throws AccountException
   {
      final UUID uuid = UUID.randomUUID();
      // would be looked up
      Account account = new Account(){
         @Override
         public UUID getId()
         {
            return uuid;
         }
      };
      
      bean.set(account.getId());
      
      return account.toString();
   }
   
}
