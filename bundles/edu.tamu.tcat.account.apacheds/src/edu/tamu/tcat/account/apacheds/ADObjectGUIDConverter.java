package edu.tamu.tcat.account.apacheds;

/**
 * Helper class to facilitate translation of MS AD/LDS GUID byte[] to String formats
 */
public class ADObjectGUIDConverter
{
   /**
    * Converts a GUID byte[] as retrieved from MS AD/LDS to a "readable" GUID value
    * of the format "xxxx-xx-xx-xx-xxxxxx"
    */
   public static String toGuidString(byte[] objectGUID)
   {
      StringBuilder uuidStr = new StringBuilder();

      int[] positions = {3,2,1,0, -1, 5,4, -1, 7,6, -1, 8,9, -1, 10,11,12,13,14,15};

      for (int pos : positions)
      {
         if (pos < 0)
         {
            uuidStr.append('-');
         }
         else
         {
            int b = (int)objectGUID[pos] & 0xFF;
            if (b <= 0xF)
               uuidStr.append('0');
            uuidStr.append(Integer.toHexString(b));
         }
      }

      return uuidStr.toString();
   }

   /**
    * Converts a GUID byte[] as retrieved from MS AD/LDS to a query key
    * of the format having with 16 "\xx" hex segments.
    * This value may be used in an LDAP query such as:
    * (objectGUID=\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01)
    */
   public static String toByteString(byte[] objectGUID)
   {
      StringBuilder out = new StringBuilder();

      for (byte b : objectGUID)
      {
         out.append('\\');
         int v = (int)b & 0xFF;
         if (v <= 0xF)
            out.append('0');
         out.append(Integer.toHexString(v));
      }

      return out.toString();
   }
}
