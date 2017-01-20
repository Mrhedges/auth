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
 * <p>
 * The default behavior requires that clients provide a valid token in order for the resource code to even execute.
 * However, this behavior may be relaxed (thereby permitting anonymous access) by setting the {@code required}
 * attribute to {@code false}. Please refer to the documentation on {@link TokenSecured#required()} for details on
 * how this attribute affects the behavior.
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

   /**
    * Indicates whether the annotated resource must be authenticated ({@code true}), or whether
    * authentication is optional ({@code false}), in which case the resource behavior will be
    * handled by the application. (default = {@code true})
    *
    * When {@code true}, failure to provide auth credentials (or providing invalid credentials)
    * will result in an "access denied" error that prevents the resource code from executing.
    *
    * When {@code false}, the resource code will be allowed to execute if the token is either
    * valid or absent, in which case the {@link ContextBean} may or may not have security context
    * info attached, respectively. Invalid tokens will result in an "access denied" alert
    * (the alternative to quietly treat the request as anonymous could be problematic if the client
    * expects to be operating with authenticated privileges).
    *
    * @return Whether the current resource requires authentication ({@code true}) or
    *         may permit anonymous access ({@code false})
    *
    * @see edu.tamu.tcat.account.jaxrs.bean.ContextBean#getOptionally
    */
   boolean required() default true;
}
