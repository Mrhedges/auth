package edu.tamu.tcat.account.apacheds.test.application;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.eclipse.core.runtime.Platform;
import org.eclipse.equinox.app.IApplication;
import org.eclipse.equinox.app.IApplicationContext;

import edu.tamu.tcat.account.apacheds.LdapHelperAdFactory;
import edu.tamu.tcat.account.apacheds.LdapHelperReader;

/**
 * This class controls all aspects of the application's execution
 */
public class Application implements IApplication
{

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
         else if (args.contains("matches"))
         {
            index = args.indexOf("-a");
            String att = args.get(index + 1);
            index = args.indexOf("-v");
            String val = args.get(index + 1);
            for (Object a : helper.getMatches(null, att, val))
               System.out.println("User [" + a + "] has attribute ["+att+"] value [" + val + "]");
         }
      }
      return IApplication.EXIT_OK;
   }

   private LdapHelperReader createLdap(String string) throws IOException
   {
      try (InputStream is = new FileInputStream(string))
      {
         Properties p = new Properties();
         p.load(is);
         return new LdapHelperAdFactory().buildReader(p);
      }
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
      System.out.println("\t[-p <user password>]");
      System.out.println("\t[-a <attribute id>]");
      System.out.println("\t[-v <value>]");

      //TODO add mutate

   }
}
