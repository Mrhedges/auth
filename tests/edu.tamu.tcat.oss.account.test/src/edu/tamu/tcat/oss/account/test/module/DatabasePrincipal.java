package edu.tamu.tcat.oss.account.test.module;

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

