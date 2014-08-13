package edu.tamu.tcat.oss.account.test;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.osgi.services.util.ServiceHelper;
import edu.tamu.tcat.oss.account.test.internal.Activator;

public class JaxRsTest
{
   protected static final String PATH_PREFIX = "/services";
   
   private Client client;
   private ServiceHelper sh;
   private WebTarget target;

   @Before
   public void createClient() throws Exception
   {
      client = ClientBuilder.newBuilder().build();
      target = client.target("http://localhost:9090" + PATH_PREFIX);
      sh = new ServiceHelper(Activator.getDefault().getContext());
      
//      ConfigurationProperties configurationProperties = sh.getService(ConfigurationProperties.class);
//      String testsAllowed = configurationProperties.getPropertyValue(TESTS_ALLOWED, String.class);
//      if (testsAllowed == null || !testsAllowed.equals("true"))
//         throw new IllegalStateException("Unit tests are disallowed by deployment");
   }

   @After
   public void teardownClient() throws Exception
   {
      client.close();
      client = null;
      sh.close();
      sh = null;
   }
   
   @Ignore
   @Test
   public void doTest() throws Exception
   {
      try
      {
         WebTarget loginTarget = target.path("mock");
         Builder builder = loginTarget.request();
         Form form = new Form().param("username", "paul.bilnoski").param("password", "pass");
         Response response = builder.post(Entity.form(form));
         int stat = response.getStatus();
         System.out.println(stat);
      }
      catch (Exception e)
      {
         e.printStackTrace();
         throw e;
      }
   }
}