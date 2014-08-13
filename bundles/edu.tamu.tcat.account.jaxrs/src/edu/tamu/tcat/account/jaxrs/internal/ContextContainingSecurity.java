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