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
package edu.tamu.tcat.account.jaxrs.bean;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.ws.rs.NameBinding;

/**
 * This annotation is processed by a DynamicFeature which adds an authn token header
 * to an HTTP response. The HTTP Method using this annotation must provide an instance
 * of the payload type to the {@link ContextBean}.
 * <p>
 * Used to annotate a method also bearing an HTTP Method annotation such as {@link javax.ws.rs.POST}.
 * <p>
 * <pre>
 *    &#64;POST &#64;TokenProviding(payloadType=UUID.class)
 *    public Object authenticate(&#64;FormParam("username") String username, &#64;FormParam("password") String password, &#64;BeanParam ContextBean bean) {
 *       UUID accountId = // authenticate and locate account ID
 *       bean.set(accountId);
 * </pre>
 */
@NameBinding
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(value = RetentionPolicy.RUNTIME)
public @interface TokenProviding
{
   /**
    * @return The type of object embedded as payload in the secure token
    */
   Class<?> payloadType();
   
   /**
    * @return An identifier defining a token processing "scope". Useful for when multiple token
    *         services exist in a system and each service can be associated with a scope.
    */
   String scopeId() default "";
   
   String label() default "";
   
   boolean strict() default true;
}
