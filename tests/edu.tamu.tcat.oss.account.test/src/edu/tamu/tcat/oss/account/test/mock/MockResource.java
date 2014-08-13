package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import javax.ws.rs.BeanParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

import edu.tamu.tcat.account.jaxrs.annotation.RequestServiceProvider;
import edu.tamu.tcat.account.jaxrs.annotation.TokenSecured;

@Path("/mock")
public class MockResource
{
   @GET
   @TokenSecured(payloadType=UUID.class)
   public String doGet(@BeanParam RequestServiceProvider sp)
   {
      System.out.println("get");
//      TokenSecured.Service<UUID> svc = sp.getService(TokenSecured.Service.class);
      return "get!";
   }
   
   @POST
   @TokenSecured(payloadType=UUID.class)
   public String doPost(@BeanParam RequestServiceProvider sp)
   {
      System.out.println("post");
//      TokenSecured.Service<UUID> svc = sp.getService(TokenSecured.Service.class);
      return "post";
   }
}
