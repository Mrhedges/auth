package edu.tamu.tcat.ldap.apacheds.test;

import java.util.Collection;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import edu.tamu.tcat.account.apacheds.LdapHelperADFactory;
import edu.tamu.tcat.account.apacheds.LdapHelperMutator;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.ldap.apacheds.test.internal.Activator;
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

         DISABLED_USER = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.user", String.class);
         DISABLED_USER_PASSWORD = exec.getPropertyValue("edu.tamu.tcat.ldap.apacheds.test.password", String.class);
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed accessing database executor", e);
      }
   }
   @Test
   public void testInit()
   {
      new LdapHelperADFactory().getWriter(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
   }

   @Test
   public void testValidUser() throws Exception
   {
      LdapHelperMutator helper = new LdapHelperADFactory().getWriter(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      LdapHelperReader helperReader = new LdapHelperADFactory().getReader(ip, port, adminUser, adminPwd, useSsl, defaultSearchOu);
      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
      Collection<?> values = helperReader.getAttributes(defaultSearchOu, "test attribute");
      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", values.contains("test value"));
      helper.removeAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
      values = helperReader.getAttributes(defaultSearchOu, "test attribute");
      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", !values.contains("test value"));
      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value");
      helper.addAttribute(defaultSearchOu, DISABLED_USER, "test attribute", "test value 2");
      helper.removeAttribute(defaultSearchOu, DISABLED_USER, "test attribute");
      values = helperReader.getAttributes(defaultSearchOu, "test attribute");
      Assert.assertTrue("Attribute not sucessfully added.  Missing from returned collection.", !values.contains("test value"));
   }

}