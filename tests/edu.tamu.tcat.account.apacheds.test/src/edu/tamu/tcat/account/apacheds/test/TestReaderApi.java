package edu.tamu.tcat.account.apacheds.test;

import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import edu.tamu.tcat.account.apacheds.LdapHelperAdFactory;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.account.apacheds.test.internal.Activator;
import edu.tamu.tcat.osgi.config.ConfigurationProperties;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

public class TestReaderApi
{
   private  String GROUP_TEST;
   private String DISABLED_USER_PASSWORD;
   private String DISABLED_USER;   
   private String VALID_USER_PASSWORD;
   private String VALID_USER;
   private String ip;
   private int port;
   private String adminUser;
   private String adminPwd;
   private boolean useSsl;
   private String defaultSearchOu;

   @Before
   public void init()
   {

      try (ServiceHelper sh = new ServiceHelper(Activator.getContext()))
      {
         ConfigurationProperties exec = sh.waitForService(ConfigurationProperties.class, 5_000);
         defaultSearchOu = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.defaultSearchOu", String.class);
         useSsl = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.useSsl", Boolean.class);
         adminPwd = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.userPassword", String.class);
         adminUser = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.userDn", String.class);
         port = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.port", Integer.class);
         ip = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.ip", String.class);

         DISABLED_USER = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.user.disabled", String.class);
         DISABLED_USER_PASSWORD = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.password.disabled", String.class);
         
         VALID_USER = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.user", String.class);
         VALID_USER_PASSWORD = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.password", String.class);
         GROUP_TEST = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.group", String.class);
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }

   @Test
   public void testInit()
   {
      new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
   }

   @Test
   public void testValidUser() throws Exception
   {
      LdapHelperReader helper = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      helper.checkValidUser(DISABLED_USER);
   }

   @Test
   public void testUserGroups() throws Exception
   {
      LdapHelperReader helper = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      List<String> groups = helper.getGroupNames(DISABLED_USER);
      Assert.assertTrue("Expected to be in at least 1 group", !groups.isEmpty());
      for (String g : groups)
         System.out.println(DISABLED_USER + " is in group " + g);
   }

   @Test
   public void testInvalidUserPassword() throws Exception
   {
      LdapHelperReader helper = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      try
      {
         helper.checkValidPassword(DISABLED_USER, DISABLED_USER_PASSWORD);
         Assert.fail("Exception expected");
      }
      catch (Exception e)
      {

      }
   }

   @Test
   public void testGroupAttribute() throws Exception
   {
      LdapHelperReader helper = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      String name = String.valueOf(helper.getAttributes(GROUP_TEST, "cn"));
      System.out.println(GROUP_TEST + " display name " + name);
   }

   public void testValidUserPassword() throws Exception
   {
      String user = VALID_USER;
      String password = VALID_USER_PASSWORD;

      LdapHelperReader helper = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);

      helper.checkValidPassword(user, password);
   }

}
