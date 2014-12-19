package edu.tamu.tcat.account.jaxrs.bean;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

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
