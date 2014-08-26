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
package edu.tamu.tcat.account.db.spi;

import java.security.Principal;
import java.util.Objects;

public abstract class DatabasePrincipal implements Principal
{
   private final String name;
   
   public DatabasePrincipal(String name)
   {
      Objects.requireNonNull(name);
      this.name = name;
   }
   
   @Override
   public String getName()
   {
      return name;
   }
   
   @Override
   public String toString()
   {
      return "DatabasePrincipal<"+getClass().getSimpleName()+">["+name+"]";
   }

   @Override
   public int hashCode()
   {
      return name.hashCode();
   }

   @Override
   public boolean equals(Object obj)
   {
      if (this == obj)
         return true;
      if (obj == null)
         return false;
      
      if (!Objects.equals(this.getClass(), obj.getClass()))
         return false;
      
      // since the types are equivalent, cast to the root type and just compare the name
      DatabasePrincipal other = (DatabasePrincipal)obj;
      if (name.equals(other.name))
         return true;
      
      return false;
   }
}

