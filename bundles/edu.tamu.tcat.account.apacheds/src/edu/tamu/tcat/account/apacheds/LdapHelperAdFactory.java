package edu.tamu.tcat.account.apacheds;

import java.util.Map;
import java.util.Properties;

import edu.tamu.tcat.account.apacheds.internal.LdapHelperAdImpl;

public class LdapHelperAdFactory
{

   private static final String DEFAULT_SEARCH_OU = "edu.tamu.tcat.ldap.ad.defaultSearchOu";
   private static final String USE_SSL = "edu.tamu.tcat.ldap.ad.useSsl";
   private static final String USE_TLS = "edu.tamu.tcat.ldap.ad.useTls";
   private static final String USER_PASSWORD = "edu.tamu.tcat.ldap.ad.userPassword";
   private static final String USER_DN = "edu.tamu.tcat.ldap.ad.userDn";
   private static final String PORT = "edu.tamu.tcat.ldap.ad.port";
   private static final String IP = "edu.tamu.tcat.ldap.ad.ip";

   public LdapHelperReader buildReader(String ip, int port, String userDn, String userPassword, boolean useSsl, boolean useTls, String defaultSearchOu){
      return buildHelper(ip, port, userDn, userPassword, useSsl, useTls, defaultSearchOu);
   }

   public LdapHelperReader buildReader(Properties props){
      return buildHelper(props);
   }
   
   public LdapHelperReader buildReader(Map<String, ?> props){
      return buildHelper(props);
   }

   public LdapHelperMutator buildWriter(String ip, int port, String userDn, String userPassword, boolean useSsl, boolean useTls, String defaultSearchOu){
      return buildHelper(ip, port, userDn, userPassword, useSsl, useTls, defaultSearchOu);
   }

   public LdapHelperMutator buildWriter(Properties props){
      return buildHelper(props);
   }
   
   public LdapHelperMutator buildWriter(Map<String, ?> props){
      return buildHelper(props);
   }

   private LdapHelperAdImpl buildHelper(Properties props)
   {
      return buildHelper(props.getProperty(IP), 
            Integer.parseInt(props.getProperty(PORT)),
            props.getProperty(USER_DN), 
            props.getProperty(USER_PASSWORD), 
            Boolean.parseBoolean(props.getProperty(USE_SSL)), 
            Boolean.parseBoolean(props.getProperty(USE_TLS)), 
            props.getProperty(DEFAULT_SEARCH_OU));
   }
   
   private LdapHelperAdImpl buildHelper(Map<String, ?> props)
   {
      return buildHelper((String)props.get(IP), 
            (Integer)props.get(PORT),
            (String)props.get(USER_DN), 
            (String)props.get(USER_PASSWORD), 
            (Boolean)props.get(USE_SSL), 
            (Boolean)props.get(USE_TLS), 
            (String)props.get(DEFAULT_SEARCH_OU));
   }
   
   private LdapHelperAdImpl buildHelper(String ip, int port, String userDn, String userPassword, boolean useSsl, boolean useTls, String defaultSearchOu){
      LdapHelperAdImpl helper = new LdapHelperAdImpl();
      helper.configure(ip, port, userDn, userPassword, useSsl, useTls, defaultSearchOu);
      helper.init();
      return helper;
   }
   
   
}
