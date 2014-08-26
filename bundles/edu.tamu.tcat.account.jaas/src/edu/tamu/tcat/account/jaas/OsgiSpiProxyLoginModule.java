/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.tamu.tcat.account.jaas;

import java.util.Map;
import java.util.Objects;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.eclipse.core.runtime.IConfigurationElement;
import org.eclipse.core.runtime.RegistryFactory;

public class OsgiSpiProxyLoginModule implements LoginModule
{
   private static final Object KEY_MODULE_ID = "osgi.proxy.moduleId";
   private LoginModule proxy;

   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
   {
      String moduleId = (String)options.get(KEY_MODULE_ID);
      if (moduleId == null || moduleId.trim().isEmpty())
         throw new IllegalStateException("Failed initializing OSGI proxy: missing parameter '"+KEY_MODULE_ID+"'");
      
      IConfigurationElement[] confs = RegistryFactory.getRegistry().getConfigurationElementsFor("edu.tamu.tcat.account.jaas","osgiModule");
      if (confs == null || confs.length == 0)
         throw new IllegalStateException("No osgi module registrations available");
      
      for (IConfigurationElement conf : confs)
      {
         try
         {
            String className = conf.getAttribute("class");
            if (Objects.equals(moduleId, className))
            {
               proxy = (LoginModule)conf.createExecutableExtension("class");
               proxy.initialize(subject, callbackHandler, sharedState, options);
               break;
            }
         }
         catch (Exception e)
         {
            throw new IllegalStateException("Failed initializing OSGI proxy ["+moduleId+"]", e);
         }
      }
      
      if (proxy == null)
         throw new IllegalStateException("Failed initializing OSGI proxy ["+moduleId+"], no contribution found matching module id");
   }

   @Override
   public boolean login() throws LoginException
   {
      return proxy.login();
   }

   @Override
   public boolean commit() throws LoginException
   {
      return proxy.commit();
   }

   @Override
   public boolean abort() throws LoginException
   {
      return proxy.abort();
   }

   @Override
   public boolean logout() throws LoginException
   {
      return proxy.logout();
   }
}
