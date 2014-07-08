package edu.tamu.tcat.oss.account.test.internal;

import org.osgi.framework.BundleContext;

import edu.tamu.tcat.osgi.services.util.ActivatorBase;

public class Activator extends ActivatorBase
{
   private static Activator instance;

   public Activator()
   {
      instance = this;
   }

   public static Activator getDefault()
   {
      return instance;
   }
   
   public static BundleContext getBundleContext()
   {
      return getDefault().getContext();
   }
}
