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

import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

import javax.security.auth.callback.Callback;

/**
 * A {@link Callback} that allows various services to be passed into
 * the {@link DatabaseLoginModule} that it requires to operate.
 * <p>
 * This is needed because JAAS login modules are constructed reflectively and treated
 * only using their base API which prevents injects of system services. Also,
 * a login module which looks up services from some service provider would couple
 * the login module to that system and make testing and mocking difficult, which is
 * not desirable. Therefore, a callback is used to allow the caller to knowingly
 * inject required services into the login module instance.
 * <p>
 * Note that instances are not {@link java.io.Serializable}.
 */
public class ServiceProviderCallback implements Callback
{
   private transient Map<Class<?>, Object> services;
   
   /**
    * Get a service by type.
    * 
    * @param cls The type of service to request.
    * @return The requested service.
    * @throws NoSuchElementException If there is no service associated with the requested type.
    */
   public <T> T getService(Class<T> cls) throws NoSuchElementException
   {
      Object svc = services.get(cls);
      if (svc == null)
         throw new NoSuchElementException("No service found for type ["+cls+"]");
      @SuppressWarnings("unchecked")
      T s = (T)svc;
      return s;
   }
   
   /**
    * Associate a service to a type in this callback. Each type may only be associated
    * with a single service instance.
    * 
    * @param type The service type.
    * @param service The service to associate with the given type.
    */
   public <T> void setService(Class<T> type, T service)
   {
      Objects.requireNonNull(type, "Service type may not be null");
      Objects.requireNonNull(service, "Instance may not be null");
      
      if (services == null)
         services = new HashMap<>();
      
      if (services.containsKey(type))
         throw new IllegalStateException("A service is already associated with type ["+type+"]");
      
      services.put(type, service);
   }
}
