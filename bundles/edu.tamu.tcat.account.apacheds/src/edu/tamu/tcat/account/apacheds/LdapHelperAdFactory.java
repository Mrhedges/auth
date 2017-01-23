package edu.tamu.tcat.account.apacheds;

import edu.tamu.tcat.account.apacheds.internal.LdapHelperAdImpl;
import edu.tamu.tcat.account.apacheds.internal.LdapSessionAdImpl;

public class LdapHelperAdFactory
{
   public LdapHelperReader buildReader(String host, int port, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls, String defaultSearchOu)
   {
      return buildHelper(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls, defaultSearchOu);
   }

   public LdapHelperMutator buildWriter(String host, int port, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls, String defaultSearchOu)
   {
      LdapHelperAdImpl helper = new LdapHelperAdImpl();
      helper.configure(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls, defaultSearchOu);
      helper.init();
      return helper;
   }

   private LdapHelperAdImpl buildHelper(String host, int port, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls, String defaultSearchOu)
   {
      LdapHelperAdImpl helper = new LdapHelperAdImpl();
      helper.configure(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls, defaultSearchOu);
      helper.init();
      return helper;
   }
   public LdapSession buildSession(String host, int port, String adminAccountDn, String adminAccountPassword, boolean useSsl, boolean useTls, String defaultSearchOu)
   {
      LdapSessionAdImpl helper = new LdapSessionAdImpl();
      helper.configure(host, port, adminAccountDn, adminAccountPassword, useSsl, useTls, defaultSearchOu);
      return helper;
   }
}
