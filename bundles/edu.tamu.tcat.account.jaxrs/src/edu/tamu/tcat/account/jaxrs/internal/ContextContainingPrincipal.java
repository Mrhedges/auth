package edu.tamu.tcat.account.jaxrs.internal;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.InterceptorContext;

//TODO: rename; really just a "map" or "provider" or "cache" Principal
public class ContextContainingPrincipal implements Principal
{
   Map<Class<?>, Object> contexts = new HashMap<>();

   @Override
   public String getName()
   {
      return null;
   }
   
   @SuppressWarnings("unchecked")
   public <T> T get(Class<T> cls)
   {
      return (T)contexts.get(cls);
   }
   
//   @SuppressWarnings("unchecked")
//   public <T> T computeIfAbsent(Class<T> cls, Supplier<T> supplier)
//   {
//      return (T)contexts.computeIfAbsent(cls, x -> supplier.get());
//   }
   
   // NOTE: not atomic. Does this need to be since the request lifecycle is synchronous?
   public Object putIfAbsent(Class<?> cls, Object obj)
   {
      Object old = contexts.get(cls);
      if (old != null)
         return old;
      contexts.put(cls, obj);
      return obj;
   }

   @Deprecated
   public static ContextContainingPrincipal setupPrincipal(ContainerRequestContext ctxRequest)
   {
      SecurityContext ctxSecurity = ctxRequest.getSecurityContext();
      Principal p = ctxSecurity.getUserPrincipal();
      if (p instanceof ContextContainingPrincipal)
      {
         ContextContainingPrincipal ccp = (ContextContainingPrincipal)p;
         return ccp;
      }
      
      ContextContainingPrincipal ccp = new ContextContainingPrincipal();
      ContextContainingSecurity sec = new ContextContainingSecurity(ccp);
      ctxRequest.setSecurityContext(sec);
      ctxRequest.setProperty(ContextContainingPrincipal.class.getName(), sec.getUserPrincipal());
      return ccp;
   }
   
   @Deprecated
   public static ContextContainingPrincipal getPrincipal(InterceptorContext context)
   {
      return (ContextContainingPrincipal)context.getProperty(ContextContainingPrincipal.class.getName());
   }
   
   @Deprecated
   public static ContextContainingPrincipal getPrincipal(ContainerRequestContext context)
   {
      return (ContextContainingPrincipal)context.getProperty(ContextContainingPrincipal.class.getName());
   }
   
//   @Deprecated
//   public static <T> T requireContext(SecurityContext context, Class<T> cls)
//   {
//      Objects.requireNonNull(context);
//      Principal principal = Objects.requireNonNull(context.getUserPrincipal());
//      if (!(principal instanceof ContextContainingPrincipal))
//         throw new NullPointerException();
//      return Objects.requireNonNull(((ContextContainingPrincipal)principal).get(cls));
//   }
}
