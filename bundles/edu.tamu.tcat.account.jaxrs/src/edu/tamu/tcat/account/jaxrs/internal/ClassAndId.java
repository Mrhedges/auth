package edu.tamu.tcat.account.jaxrs.internal;

/**
 * Simple container for a class and id (String) object used as a key in a map.
 */
public class ClassAndId
{
   public final Class<?> cls;
   public final String id;
   public ClassAndId(Class<?> cls, String id)
   {
      this.cls = cls;
      this.id = id;
   }
   @Override
   public int hashCode()
   {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((cls == null) ? 0 : cls.hashCode());
      result = prime * result + ((id == null) ? 0 : id.hashCode());
      return result;
   }
   @Override
   public boolean equals(Object obj)
   {
      if (this == obj)
         return true;
      if (obj == null)
         return false;
      if (getClass() != obj.getClass())
         return false;
      ClassAndId other = (ClassAndId)obj;
      if (cls == null)
      {
         if (other.cls != null)
            return false;
      }
      else if (!cls.equals(other.cls))
         return false;
      if (id == null)
      {
         if (other.id != null)
            return false;
      }
      else if (!id.equals(other.id))
         return false;
      return true;
   }
}