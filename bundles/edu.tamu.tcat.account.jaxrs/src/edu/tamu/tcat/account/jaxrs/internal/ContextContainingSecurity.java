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
package edu.tamu.tcat.account.jaxrs.internal;

import javax.ws.rs.core.SecurityContext;

class ContextContainingSecurity implements SecurityContext
{
   private final ContextContainingPrincipal principal;

   public ContextContainingSecurity(ContextContainingPrincipal principal)
   {
      this.principal = principal;
   }
   
   @Override
   public ContextContainingPrincipal getUserPrincipal()
   {
      return principal;
   }

   @Override
   public boolean isUserInRole(String role)
   {
      return false;
   }

   @Override
   public boolean isSecure()
   {
      return false;
   }

   @Override
   public String getAuthenticationScheme()
   {
      return null;
   }
   
}