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
package edu.tamu.tcat.account.login;


/**
 * The entry point to the account login (authentication) framework. This type
 * represents a base that implementations must implement to provide a common
 * API. This framework is designed to wrap JAAS and work together with it, and to
 * leverage some of its good parts.
 * <p>
 * Instance are not thread-safe and are intended for single use for the purpose of
 * logging in to a secured application. The result of the process started by
 * invoking {@link #login()} provides a {@link LoginData}
 * which may be used to find an {@link edu.tamu.tcat.account.Account} for the application
 * and may be found using an {@link edu.tamu.tcat.account.store.AccountStore}.
 * <p>
 * Specific implementations should be default-constructible to allow for flexible
 * instantiation and instance control, but may require
 * implementation-specific initialization and configuration. One such implementation may
 * simply delegate to the JAAS authentication entry point (i.e.
 * {@link javax.security.auth.login.LoginContext}),
 * and utilize its configuration and class-loading mechanisms.
 */
public interface LoginProvider
{
   /**
    * Execute processing of internal configuration to authenticate an account.
    *
    * @return A {@link LoginData} encapsulating account information, or {@code null}
    *         if authentication failed.
    */
   LoginData login();
}
