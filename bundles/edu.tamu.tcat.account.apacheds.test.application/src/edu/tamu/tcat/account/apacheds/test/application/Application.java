package edu.tamu.tcat.account.apacheds.test.application;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.eclipse.core.runtime.Platform;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;

import edu.tamu.tcat.account.apacheds.LdapHelperAdFactory;
import edu.tamu.tcat.account.apacheds.LdapHelperMutator;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;
import edu.tamu.tcat.account.apacheds.LdapSession;

/**
 * This class controls all aspects of the application's execution
 */
public class Application implements IApplication
{
   private static final String DEFAULT_SEARCH_OU = "edu.tamu.tcat.ldap.ad.defaultSearchOu";
   private static final String USE_SSL = "edu.tamu.tcat.ldap.ad.useSsl";
   private static final String USE_TLS = "edu.tamu.tcat.ldap.ad.useTls";
   private static final String USER_PASSWORD = "edu.tamu.tcat.ldap.ad.userPassword";
   private static final String USER_DN = "edu.tamu.tcat.ldap.ad.userDn";
   private static final String PORT = "edu.tamu.tcat.ldap.ad.port";
   private static final String IP = "edu.tamu.tcat.ldap.ad.ip";

   /*
    * (non-Javadoc)
    * @see org.eclipse.equinox.app.IApplication#start(org.eclipse.equinox.app.IApplicationContext)
    */
   public Object start(IApplicationContext context) throws Exception
   {
      List<String> args = Arrays.asList(Platform.getCommandLineArgs());
      if (args.contains("-h"))
      {
         printHelp();
      }
      else if (!args.contains("-f"))
      {
         System.out.println("ldap configuration file must be specified");
         printHelp();
      }
      else if (args.contains("matches"))
      {
         int index = args.indexOf("-f");
         try (LdapSession helper = createLdapSession(args.get(index + 1)))
         {
            index = args.indexOf("-a");
            String att = args.get(index + 1);
            index = args.indexOf("-v");
            String val = args.get(index + 1);
//            for (int i = 0; i < 10000; i++)
            {
               for (Object a : helper.getMatches(null, att, val))
                  System.out.println("User [" + a + "] has attribute [" + att + "] value [" + val + "]");
            }
            System.out.println("thread check");
         }
      }
      else if (args.contains("ldsPwdChange"))
      {
         int index = args.indexOf("-f");
         try (LdapSession helper = createLdapSession(args.get(index + 1)))
         {
            index = args.indexOf("-u");
            String user = args.get(index + 1);
            index = args.indexOf("-p");
            String password = args.get(index + 1);
            helper.changePasswordUserPassword(user, password);
            System.out.println("Password changed to ["+password+"]");
         }
      }
      else if (args.contains("adPwdChange"))
      {
         int index = args.indexOf("-f");
         try (LdapSession helper = createLdapSession(args.get(index + 1)))
         {
            index = args.indexOf("-u");
            String user = args.get(index + 1);
            index = args.indexOf("-p");
            String password = args.get(index + 1);
            helper.changePasswordUnicodePassword(user, password);
            System.out.println("Password changed to ["+password+"]");
         }
      }
      else if (args.contains("addUser"))
      {
         int index = args.indexOf("-f");
         try (LdapSession helper = createLdapSession(args.get(index + 1)))
         {
             index = args.indexOf("-cn");
             String cn = args.get(index + 1);
             index = args.indexOf("-ou");
             String ou = args.get(index + 1);
             index = args.indexOf("-u");
             String userName = args.get(index + 1);
             List<String> objClasses = Arrays.asList("organizationalPerson", "person", "top", "user");
 			 String instanceType="4";
 			 String objectCategory = "CN=Person,CN=Schema,CN=Configuration,CN={DC42C6A0-6A5A-4683-9B9C-E7B7C93E30E9}";
 			
 			Map <String,String> attributes = new HashMap<>();
 			attributes.put("distinguishedName", "CN="+cn+",OU="+ou);
 			attributes.put("msDS-UserAccountDisabled", "FALSE");
 			attributes.put("msDS-UserDontExpirePassword", "TRUE");
 			attributes.put("name", cn);
 			attributes.put("sAMAccountName", userName);
             
            helper.createUser(cn, ou, "1Password2", null, objClasses, instanceType, objectCategory, attributes);
         }
      }
      else if (!args.contains("-u"))
      {
         System.out.println("user distinguished name must be specified");
         printHelp();
      }
      else
      {
         int index = args.indexOf("-f");
         LdapHelperReader helper = createLdap(args.get(index + 1));
         index = args.indexOf("-u");
         String user = args.get(index + 1);
         if (args.contains("testUser"))
         {
            helper.checkValidUser(user);
            System.out.println("User [" + user + "] is a valid user");
         }
         else if (args.contains("testPassword"))
         {
            index = args.indexOf("-p");
            helper.checkValidPassword(user, args.get(index + 1));
            System.out.println("User [" + user + "] has a valid credentials");
         }
         else if (args.contains("groups"))
         {
            for (String g : helper.getGroupNames(user))
               System.out.println("User [" + user + "] is in group [" + g + "]");
         }
         else if (args.contains("attribute"))
         {
            index = args.indexOf("-a");
            String attr = args.get(index + 1);
            for (Object a : helper.getAttributes(user, attr))
               System.out.println("User [" + user + "] is has attribute ["+attr+"] value [" + a + "]");
         }
         else if (args.contains("member"))
         {
            index = args.indexOf("-g");
            String group = args.get(index + 1);
            System.out.println("User [" + user + "] is "+ (helper.isMemberOf(group, user) ? "" : "not")+" a member of group ["+group+"]");
         }
      }
      
      // catch exception and print it & return exit not ok
      return IApplication.EXIT_OK;
   }

   private LdapHelperReader createLdap(String string) throws IOException
   {
      Properties props = new Properties();
      try (InputStream is = new FileInputStream(string))
      {
         props.load(is);
      }

      return new LdapHelperAdFactory().buildReader(props.getProperty(IP),
            Integer.parseInt(props.getProperty(PORT)),
            props.getProperty(USER_DN),
            props.getProperty(USER_PASSWORD),
            Boolean.parseBoolean(props.getProperty(USE_SSL)),
            Boolean.parseBoolean(props.getProperty(USE_TLS)),
            props.getProperty(DEFAULT_SEARCH_OU));
   }
   
   private LdapHelperMutator createLdapMutator(String string) throws IOException
   {
      Properties props = new Properties();
      try (InputStream is = new FileInputStream(string))
      {
         props.load(is);
      }

      return new LdapHelperAdFactory().buildWriter(props.getProperty(IP),
            Integer.parseInt(props.getProperty(PORT)),
            props.getProperty(USER_DN),
            props.getProperty(USER_PASSWORD),
            Boolean.parseBoolean(props.getProperty(USE_SSL)),
            Boolean.parseBoolean(props.getProperty(USE_TLS)),
            props.getProperty(DEFAULT_SEARCH_OU));
   }
   
   private LdapSession createLdapSession(String string) throws IOException
   {
      Properties props = new Properties();
      try (InputStream is = new FileInputStream(string))
      {
         props.load(is);
      }

      return new LdapHelperAdFactory().buildSession(props.getProperty(IP),
            Integer.parseInt(props.getProperty(PORT)),
            props.getProperty(USER_DN),
            props.getProperty(USER_PASSWORD),
            Boolean.parseBoolean(props.getProperty(USE_SSL)),
            Boolean.parseBoolean(props.getProperty(USE_TLS)),
            props.getProperty(DEFAULT_SEARCH_OU));
   }

   /*
    * (non-Javadoc)
    * @see org.eclipse.equinox.app.IApplication#stop()
    */
   public void stop()
   {
      // nothing to do
   }

   private void printHelp()
   {
      System.out.println("Options are:");
      System.out.println("\t-f <configurationFile>");
      System.out.println("\t-u <user distinguished name>");
      System.out.println("\t<testUser {does this user exist} | ");
      System.out.println("\t\ttestPassword {does this user password combination validate} | ");
      System.out.println("\t\tgroups {get the groups of user} | ");
      System.out.println("\t\tmatches {get the users matching an attribute value pair} | ");
      System.out.println("\t\tattribute {get the specified attributes for this user} >");
      System.out.println("\t\tmember {tests membership in a group for a user} >");
      System.out.println("\t[-p <user password>]");
      System.out.println("\t[-a <attribute id>]");
      System.out.println("\t[-v <value>]");
      System.out.println("\t[-g <group distinguished name>]");

      //TODO add mutate

   }
}
