package edu.tamu.tcat.account.jaxrs.bean;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation is processed by a DynamicFeature which adds an authn signature header
 * to an HTTP response.
 * <p>
 * Used to annotate a method also bearing an HTTP Method annotation such as {@link javax.ws.rs.POST}.
 * <p>
 * A method, such as:
 * <pre>
 * &#64;GET &#64;SignatureSecured(payloadType=UUID.class)
 * public Object getObject(&#64;BeanParam ContextBean bean) {
 *    UUID accountId = bean.get(UUID.class);
 * </pre>
 * Will have a {@link ContextBean} with the requested payload.
 */
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(value = RetentionPolicy.RUNTIME)
public @interface SignatureSecured
{
   /**
    * @return The type of object representative of the signature. 
    */
   Class<?> payloadType();
   
   /**
    * @return An identifier defining a signature processing "scope". Useful for when multiple signature
    *         services exist in a system and each service can be associated with a scope.
    */
   String scopeId() default "";
   
   /**
    * @return A label used to distinguish this annotation from others of the same type
    */
   String label() default "";
}
