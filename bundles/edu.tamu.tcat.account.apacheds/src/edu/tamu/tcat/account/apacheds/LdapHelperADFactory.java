package edu.tamu.tcat.account.apacheds;

import java.util.Properties;

import edu.tamu.tcat.account.apacheds.internal.LdapHelperAdImpl;

public class LdapHelperADFactory
{

   private static final String DEFAULT_SEARCH_OU = "edu.tamu.tcat.ldap.ad.defaultSearchOu";
   private static final String USE_SSL = "edu.tamu.tcat.ldap.ad.useSsl";
   private static final String USER_PASSWORD = "edu.tamu.tcat.ldap.ad.userPassword";
   private static final String USER_DN = "edu.tamu.tcat.ldap.ad.userDn";
   private static final String PORT = "edu.tamu.tcat.ldap.ad.port";
   private static final String IP = "edu.tamu.tcat.ldap.ad.ip";

   public LdapHelperReader getReader(String ip, int port, String userDn, String userPassword, boolean useSsl, String defaultSearchOu){
      return getHelper(ip, port, userDn, userPassword, useSsl, defaultSearchOu);
   }

   public LdapHelperReader getReader(Properties props){
      return getHelper(props);
   }

   public LdapHelperMutator getWriter(String ip, int port, String userDn, String userPassword, boolean useSsl, String defaultSearchOu){
      return getHelper(ip, port, userDn, userPassword, useSsl, defaultSearchOu);
   }
   
   public LdapHelperMutator getWriter(Properties props){
      return getHelper(props);
   }
   
   private LdapHelperAdImpl getHelper(Properties props)
   {
      return getHelper(props.getProperty(IP), 
            Integer.parseInt(props.getProperty(PORT)),
            props.getProperty(USER_DN), 
            props.getProperty(USER_PASSWORD), 
            Boolean.parseBoolean(props.getProperty(USE_SSL)), 
            props.getProperty(DEFAULT_SEARCH_OU));
   }
   
   private LdapHelperAdImpl getHelper(String ip, int port, String userDn, String userPassword, boolean useSsl, String defaultSearchOu){
      LdapHelperAdImpl helper = new LdapHelperAdImpl();
      helper.configure(ip, port, userDn, userPassword, useSsl, defaultSearchOu);
      helper.init();
      return helper;
   }
   
   
}
