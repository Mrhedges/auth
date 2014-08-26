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

import java.security.Principal;

import javax.security.auth.spi.LoginModule;

import edu.tamu.tcat.account.login.LoginData;

/**
 * A JAAS {@link Principal} that provides access to a {@link LoginData}, allowing a
 * {@link LoginModule} to expose one through the JAAS API.
 * <p>
 * If one of these is needed and a <tt>LoginModule</tt> does not provide one,
 * the caller will need to construct a <tt>LoginData</tt> from
 * the <tt>Principal</tt>s known to be provided by that <tt>LoginModule</tt>.
 */
public interface LoginDataPrincipal extends Principal
{
   LoginData getLoginData();
}
