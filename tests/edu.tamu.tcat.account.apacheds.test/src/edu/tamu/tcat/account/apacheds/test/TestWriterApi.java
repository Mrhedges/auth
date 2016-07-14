package edu.tamu.tcat.account.apacheds.test;

import java.util.Collection;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import edu.tamu.tcat.account.apacheds.LdapHelperAdFactory;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.account.apacheds.test.internal.Activator;
import edu.tamu.tcat.osgi.config.ConfigurationProperties;
import edu.tamu.tcat.osgi.services.util.ServiceHelper;

public class TestWriterApi
{
   private String DISABLED_USER_PASSWORD;
   private String DISABLED_USER;
   private String ip;
   private int port;
   private String adminUser;
   private String adminPwd;
   private boolean useSsl;
   private boolean useTls;
   private String defaultSearchOu;

   @Before
   public void init()
   {

      try (ServiceHelper sh = new ServiceHelper(Activator.getContext()))
      {
         ConfigurationProperties exec = sh.waitForService(ConfigurationProperties.class, 5_000);
         defaultSearchOu = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.defaultSearchOu", String.class);
         useSsl = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.useSsl", Boolean.class);
         useTls = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.useTls", Boolean.class);
         adminPwd = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.userPassword", String.class);
         adminUser = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.userDn", String.class);
         port = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.port", Integer.class);
         ip = exec.getPropertyValue("edu.tamu.tcat.ldap.ad.ip", String.class);

         DISABLED_USER = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.user", String.class);
         DISABLED_USER_PASSWORD = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.password", String.class);
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }

   //FIXME: replace when the writer is implemented
//   @Test
//   public void testInit()
//   {
//      new LdapHelperAdFactory().buildWriter(ip, port, adminUser, adminPwd, useSsl, useTls, defaultSearchOu);
//   }
//
//   @Test
//   public void testValidUser() throws Exception
//   {
//      LdapHelperMutator helper = new LdapHelperAdFactory().buildWriter(ip, port, adminUser, adminPwd, useSsl, useTls, defaultSearchOu);
//      LdapHelperReader helperReader = new LdapHelperAdFactory().buildReader(ip, port, adminUser, adminPwd, useSsl, useTls, defaultSearchOu);
//      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
//      Collection<?> values = helperReader.getAttributes(defaultSearchOu, "test attribute");
//      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", values.contains("test value"));
//      helper.removeAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
//      values = helperReader.getAttributes(defaultSearchOu, "test attribute");
//      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", !values.contains("test value"));
//      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
//      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value 2");
//      helper.removeAttribute(defaultSearchOu, DISABLED_USER, "test attribute");
//      values = helperReader.getAttributes(defaultSearchOu, "test attribute");
//      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", !values.contains("test value"));
//   }

}
