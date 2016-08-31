package edu.tamu.tcat.account.apacheds.internal;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

import edu.tamu.tcat.account.apacheds.LdapAuthException;
import edu.tamu.tcat.account.apacheds.LdapException;
import edu.tamu.tcat.account.apacheds.LdapSession;

/**
 * This wrapper on {@link LdapHelperAdImpl} that maintains a consistent anonymously bound connection.<br>
 * This is intended to address the issue in underlying libraries that spawn Threads with each new connection or binding which are not cleaned up when the connection is unbound / closed
 * */
public class LdapSessionAdImpl implements LdapSession
{
   private Logger logger = Logger.getLogger(getClass().getName());
   private LdapConnectionConfig config = null;
   private LdapConnection boundConnection = null;
   private LdapConnection unboundConnection = null;
   private LdapHelperAdImpl helper = new LdapHelperAdImpl(); 
   
   private synchronized void init() throws LdapException
   {
      if(unboundConnection != null)
      {
         // need to verify connection is still valid and has not timed out or otherwise failed
         if(!unboundConnection.isConnected())
            try
            {
               logger.info("Replacing Unbounded connection.");
               unboundConnection.close();
            }
            catch (IOException e)
            {
               logger.log(Level.WARNING, "Abandoning connection", e);
            }
            finally
            {
               unboundConnection = null;
            }
      }
      if(boundConnection != null)
      {
         // need to verify connection is still valid and has not timed out or otherwise failed
         if (!boundConnection.isConnected())
            try
            {
               logger.info("Replacing Bounded connection.");
               boundConnection.close();
            }
            catch (IOException e)
            {
               logger.log(Level.WARNING, "Abandoning connection", e);
            }
            finally
            {
               boundConnection = null;
            }
      }
      if(boundConnection !=null && unboundConnection != null)
         return;
      helper.init();
      if (unboundConnection == null)
      {
         unboundConnection = new LdapNetworkConnection(config);
      }

      try
      {
         if (boundConnection == null)
         {
            boundConnection = new LdapNetworkConnection(config);
            boundConnection.bind();
         }
      }
      catch (org.apache.directory.api.ldap.model.exception.LdapException e)
      {
         try
         {
            boundConnection.close();
         }
         catch (IOException e1)
         {
            e.addSuppressed(e1);
            throw new LdapException("Failed to close connection", e);
         }
         boundConnection = null;
         throw new LdapException("Failed to bind connection", e);
      }
   }
   
   public void configure(String ip, int port, String userDn, String userPassword, boolean useSsl, boolean useTls, String defaultSearchOu)
   {
      config = new LdapConnectionConfig();
      config.setLdapHost(ip);
      config.setLdapPort(port);
      config.setName(userDn);
      config.setCredentials(userPassword);
      config.setUseSsl(useSsl);
      config.setUseTls(useTls);
      helper.configure(ip, port, userDn, userPassword, useSsl, useTls, defaultSearchOu);
   }
   
   public synchronized void close() throws Exception
   {
      if(boundConnection !=null)
      {
         boundConnection.unBind();
         boundConnection.close();
      }
      if(unboundConnection !=null)
      {
         unboundConnection.close();
      }
      boundConnection = null;
   }

   @Override
   public void checkValidPassword(String userDistinguishedName, String password) throws LdapException, LdapAuthException
   {
      init();
      helper.checkValidPassword(userDistinguishedName, password, unboundConnection);
   }

   @Override
   public List<String> getGroupNamesAndValidate(String userDistinguishedName, String password) throws LdapException, LdapAuthException
   {
      init();
      return helper.getGroupNamesAndValidate(userDistinguishedName, password);
   }

   @Override
   public List<String> getGroupNamesAndValidate(String ouSearchPrefix, String userDistinguishedName, String password) throws LdapException
   {
      init();
      return helper.getGroupNamesAndValidate(ouSearchPrefix, userDistinguishedName, password);
   }
   
   @Override
   public void checkValidUser(String user) throws LdapException, LdapAuthException
   {
      init();
      helper.checkValidUser(helper.computeDefaultOu(user), user, boundConnection);
   }

   @Override
   public void checkValidUser(String ouSearchPrefix, String userDistinguishedName) throws LdapException, LdapAuthException
   {
      init();
      helper.checkValidUser(ouSearchPrefix, userDistinguishedName, boundConnection);
   }

   @Override
   public Map<String, Collection<Object>> getAttributes(String userDistinguishedName, Collection<String> attributeId) throws LdapException
   {
      return getAttributes(helper.computeDefaultOu(userDistinguishedName), userDistinguishedName, attributeId);
   }

   @Override
   public Map<String, Collection<Object>> getAttributes(String ouSearchPrefix, String userDistinguishedName, Collection<String> attributeId) throws LdapException
   {
      init();
      return helper.getAttributes(ouSearchPrefix, userDistinguishedName, attributeId, boundConnection);
   }

   @Override
   public boolean isMemberOf(String groupDn, String userDn) throws LdapException
   {
      init();
      return helper.isMemberOf(groupDn, userDn, boundConnection);
   }

   @Override
   public List<String> getMemberNamesOfGroup(String ouSearchPrefix, String groupDistinguishedName) throws LdapException
   {
      init();
      List<String> members = new CopyOnWriteArrayList<>();
      helper.getMemberNamesOfGroupInternal(members, groupDistinguishedName, boundConnection);
      return new ArrayList<>(members);
   }

   @Override
   public List<String> getMemberNamesOfGroup(String groupDistinguishedName) throws LdapException
   {
      return getMemberNamesOfGroup(null, groupDistinguishedName);
   }

   @Override
   public List<String> getGroupNames(String userDistinguishedName) throws LdapException
   {
      return getGroupNames(helper.computeDefaultOu(userDistinguishedName), userDistinguishedName);
   }

   @Override
   public List<String> getGroupNames(String ouSearchPrefix, String userDistinguishedName) throws LdapException, LdapAuthException
   {
      init();
      List<String> groups = helper.getAttributes(ouSearchPrefix, userDistinguishedName, Collections.singleton("memberof"), boundConnection).get("memberof").stream()
            .map(String::valueOf)
            .collect(Collectors.toList());
      Set<String> recursiveGroups = new HashSet<>(groups);
      groups.forEach(g -> helper.getGroupsInternal(g, recursiveGroups, boundConnection));
      return new ArrayList<>(recursiveGroups);
   }

   @Override
   public List<String> getMatches(String ouSearchPrefix, String attribute, String value, boolean caseSensitive) throws LdapException
   {
      init();
      return helper.getMatchesInternal(ouSearchPrefix, attribute, value, caseSensitive, boundConnection);
   }

   @Override
   public List<String> getMatches(String ouSearchPrefix, String attribute, byte[] value) throws LdapException
   {
      init();
      return helper.getMatchesInternal(ouSearchPrefix, attribute, value, boundConnection);
   }
}
