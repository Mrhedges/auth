package edu.tamu.tcat.account.jaxrs.bean;

import java.security.Principal;
import java.util.Objects;

import javax.ws.rs.BeanParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.InterceptorContext;

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
   private final ContextContainingPrincipal ccp;

   /**
    * Constructor used when provided to an HTTP Method method using {@code @BeanParam}
    * @param context
    */
   public ContextBean(@Context SecurityContext context)
   {
      Objects.requireNonNull(context);
      Principal principal = Objects.requireNonNull(context.getUserPrincipal());
      if (!(principal instanceof ContextContainingPrincipal))
         throw new IllegalStateException("Context Provider not initialized");
      this.ccp = (ContextContainingPrincipal)principal;
   }
   
   private static <T> Container<T> getWrapper(ContextContainingPrincipal ccp, Class<T> type) throws AccountException
   {
      Container<T> wr = (Container)ccp.get(type);
      if (wr == null)
         throw new AccountException("No context found of the requested type ["+type+"]");
      return wr;
   }
   
   // called by HTTP Method impls after constructor
   public <T> T get(Class<T> type) throws AccountException
   {
      return getWrapper(ccp, type).get();
   }
   
   /**
    * Set the given instance as the new value for the wrapper of its type.
    * <p>
    * Since this {@link ContextBean} is intended to store simple types, the actual
    * concrete type of the instance passed is used to determine the wrapper in which
    * it belongs.
    * 
    * @param obj
    * @throws AccountException
    */
   public <T> void set(T obj) throws AccountException
   {
      Class<T> cls = (Class)obj.getClass();
      getWrapper(ccp, cls).set(obj);
   }
   
   public static class Container<PT>
   {
      private PT payload;
      
      public PT get()
      {
         return payload;
      }
      
      public void set(PT obj)
      {
         payload = obj;
      }
   }
   
   public interface Installer
   {
      /**
       * Install a {@link Container} of the given payload type into the active context.
       * 
       * @param payloadType
       * @return
       * @throws AccountException
       */
      // called by @Provider impls
      <T> Container<T> install(Class<T> payloadType) throws AccountException;
   }
   
   private static class InstallerImpl implements Installer
   {
      private ContextContainingPrincipal princ;
      
      @Override
      public <T> Container<T> install(Class<T> payloadType) throws AccountException
      {
         try
         {
            Container<T> wr = new Container<T>();
            
            Container<T> existing = (Container)princ.putIfAbsent(payloadType, wr);
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
      InstallerImpl inst = new InstallerImpl();
      inst.princ = ContextContainingPrincipal.setupPrincipal(contextRequest);
      return inst;
   }

   /**
    * Factory method to use within a {@link ContainerRequestFilter}.
    * <p>
    * Unlike {@link #from(ContainerRequestContext)}, this method requires the principal to already
    * have been initialized by a call to that method by some other provider previously invoked in
    * the HTTP Response call sequence.
    * 
    * @param context
    * @throws AccountException If the context bean container is not initialized.
    */
   // Installs the ContextContainingPrinciple in the request context's SecurityContext if not yet there
   public static Installer from(InterceptorContext ctx) throws AccountException
   {
      // set up the app-context if not yet there
      InstallerImpl inst = new InstallerImpl();
      inst.princ = ContextContainingPrincipal.getPrincipal(ctx);
      if (inst.princ == null)
         throw new AccountException("Context not initialized with principal");
      return inst;
   }
   
   /**
    * Convenience method to extract the stored value of the given type from the given request context.
    * 
    * @param ctx
    * @param type
    * @return The current value in the {@link Container} for the given type. May be {@code null}
    * @throws AccountException If no container is installed for the given type
    */
   public static <T> T getValue(ContainerRequestContext ctx, Class<T> type) throws AccountException
   {
      return new ContextBean(ctx.getSecurityContext()).get(type);
   }
   
   /**
    * Convenience method to extract the stored value of the given type from the given request context.
    * 
    * @param ctx
    * @param type
    * @return The current value in the {@link Container} for the given type. May be {@code null}
    * @throws AccountException If no container is installed for the given type
    */
   public static <T> T getValue(InterceptorContext ctx, Class<T> type) throws AccountException
   {
      Container<T> pw = getWrapper(ContextContainingPrincipal.getPrincipal(ctx), type);
      return pw.get();
   }
}
