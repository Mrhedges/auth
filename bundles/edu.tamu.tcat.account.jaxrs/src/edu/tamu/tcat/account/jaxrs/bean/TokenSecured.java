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

/**
 * This annotation is processed by a {@link javax.ws.rs.container.ContainerRequestFilter} which processes
 * authorization data from an HTTP request. The implementation and configuration of the filter
 * determines the portion of the request used and format of the data, and results in an object
 * of the requested payload type being injected into the {@link ContextBean}.
 * <p>
 * Used to annotate a (Java) method also bearing an HTTP Method annotation such as {@link javax.ws.rs.POST}.
 * <p>
 * A method, such as:
 * <pre>
 * &#64;GET &#64;TokenSecured(payloadType=UUID.class)
 * public Response getObject(&#64;BeanParam ContextBean bean) {
 *    UUID accountId = bean.get(UUID.class);
 *    // construct and return response using authenticated user with id = accountId
 * }
 * </pre>
 * Will have a {@link ContextBean} with the requested payload.
 *
 * @see edu.tamu.tcat.account.jaxrs.provider.token.TokenSecurityObjectFilter
 */
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(value = RetentionPolicy.RUNTIME)
public @interface TokenSecured
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

   /**
    * @return A label used to distinguish this annotation from others of the same type
    */
   String label() default "";
}
