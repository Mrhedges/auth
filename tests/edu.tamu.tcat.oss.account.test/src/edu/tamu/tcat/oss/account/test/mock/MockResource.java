package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import javax.ws.rs.BeanParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.bean.ContextBean;
import edu.tamu.tcat.account.jaxrs.bean.TokenSecured;

@Path("/mock")
public class MockResource
{
   @GET
   @TokenSecured(payloadType=UUID.class)
   public String doGet(@BeanParam ContextBean bean)
   {
      System.out.println("get");
//      TokenSecured.Service<UUID> svc = bean.get(TokenSecured.Service.class);
      return "get!";
   }
   
   @POST
   @TokenSecured(payloadType=UUID.class)
   public String doPost(@BeanParam ContextBean bean) throws AccountException
   {
      System.out.println("post");
      UUID uuid = bean.get(UUID.class);
      return "post";
   }
}
