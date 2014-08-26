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
 * This annotation is processed by a DynamicFeature which adds an authn token header
 * to an HTTP response.
 * <p>
 * Used to annotate a method also bearing an HTTP Method annotation such as {@link javax.ws.rs.POST}.
 * <p>
 * A method, such as:
 * <pre>
 * &#64;GET &#64;TokenSecured public Object getObject(@Context SecurityContext context) {
 *    TokenSecuredContext tokenSecuredContext = ContextContainingPrincipal.requireContext(context, TokenSecuredContext.class);
 *    UUID accountId = tokenSecuredContext.uuid;
 * </pre>
 * Will have a {@link TokenSecuredContext} availabler in the provided {@code context}
 */
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(value = RetentionPolicy.RUNTIME)
public @interface TokenSecured
{
   Class<?> payloadType();
}
