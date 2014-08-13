package edu.tamu.tcat.account.jaxrs.bean;

import java.security.Principal;
import java.util.Objects;

import javax.ws.rs.BeanParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.jaxrs.internal.ContextContainingPrincipal;

/**
 * Acts as a bean to extract and provide access to data packaged
 * into a {@link SecurityContext}. To be used
 * as a {@link BeanParam &#64;BeanParam} for HTTP Methods.
 * <p>
 * This could also be used as a base class and extended by the application to add other injects.
 * These may be injected into a constructor or annotated fields.
 * Other
 * injects include {@code @PathParam}, {@code @HeaderParam},
 * {@code @FormParam}, {@code @QueryParam} and {@code @CookieParam}.
 * 
 * @see BeanParam
 */
public class ContextBean
{
   private SecurityContext context;
   private ContextContainingPrincipal ccp;

   /**
    * Constructor used when provided to an HTTP Method method using {@code @BeanParam}
    * @param context
    */
   public ContextBean(@Context SecurityContext context)
   {
      Objects.requireNonNull(context);
      this.context = context;
      Principal principal = Objects.requireNonNull(context.getUserPrincipal());
      if (!(principal instanceof ContextContainingPrincipal))
         throw new IllegalStateException("Context Provider not initialized");
      this.ccp = (ContextContainingPrincipal)principal;
   }
   
   // called by HTTP Method impls after constructor
   public <T> T get(Class<T> type) throws AccountException
   {
      PayloadWrapper<T> wr = (PayloadWrapper)ccp.get(type);
      if (wr == null)
         throw new AccountException("No context found of the requested type");
      return wr.get();
   }
   
   public static class PayloadWrapper<PT>
   {
      PT payload;
      
      public PT get()
      {
         return payload;
      }
      
      public void set(PT obj)
      {
         payload = obj;
      }
   }
   
   public static class Installer
   {
      private ContainerRequestContext contextRequest;
      private ContextContainingPrincipal princ;
      
      /**
       * Install a {@link PayloadWrapper} of the given payload type into the active context.
       * 
       * @param payloadType
       * @return
       * @throws AccountException
       */
      // called by @Provider impls
      public <T> PayloadWrapper<T> install(Class<T> payloadType) throws AccountException
      {
         try
         {
            PayloadWrapper<T> wr = new PayloadWrapper<T>();
            
            PayloadWrapper<T> existing = (PayloadWrapper)princ.putIfAbsent(payloadType, wr);
            return existing;
         }
         catch (Exception e)
         {
            throw new AccountException("Failed installing bean of payload type ["+payloadType+"]", e);
         }
      }
   }
   
   /**
    * Factory method to use within a {@link ContainerRequestFilter}.
    * 
    * @param context
    * @return
    */
   // Installs the ContextContainingPrinciple in the request context's SecurityContext if not yet there
   public static Installer from(ContainerRequestContext contextRequest)
   {
      // set up the app-context if not yet there
      Installer inst = new Installer();
      inst.contextRequest = contextRequest;
      inst.princ = ContextContainingPrincipal.setupPrincipal(contextRequest);
      return inst;
   }

   /**
    * Convenience method to extract the payload of the given type from the given request context.
    * 
    * @param requestContext
    * @param type
    * @return
    * @throws AccountException
    */
   public static <T> T getValue(ContainerRequestContext requestContext, Class<T> type) throws AccountException
   {
      return new ContextBean(requestContext.getSecurityContext()).get(type);
   }
}
