package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.ReaderInterceptor;

import edu.tamu.tcat.account.jaxrs.bean.SignatureSecured;
import edu.tamu.tcat.account.jaxrs.internal.ClassAndId;
import edu.tamu.tcat.account.signature.SignatureService;

@Provider
public class SignatureDynamicFeature implements DynamicFeature
{
   private static final String SCOPE_ID_KEY = "scopeId";
   
   private Map<ClassAndId, SignatureService<?>> signatureServices = new HashMap<>();

   public synchronized void bind(SignatureService<?> svc, Map<String, Object> properties)
   {
      ClassAndId classAndId = getClassAndId(svc, properties);
      
      signatureServices.put(classAndId, svc);
   }

   private ClassAndId getClassAndId(SignatureService<?> svc, Map<String, Object> properties)
   {
      Class<?> payloadType = svc.getPayloadType();
      String id = (String)properties.get(SCOPE_ID_KEY);
      if (id == null)
      {
         id = "";
      }
      ClassAndId classAndId = new ClassAndId(payloadType, id);
      return classAndId;
   }
   
   public synchronized void unbind(SignatureService<?> svc, Map<String, Object> properties)
   {
      ClassAndId classAndId = getClassAndId(svc, properties);
      signatureServices.remove(classAndId);
   }
   
   public void activate()
   {
   }
   
   @Override
   public void configure(ResourceInfo resourceInfo, FeatureContext context)
   {
      Method method = resourceInfo.getResourceMethod();
      SignatureSecured signatureSecured = method.getAnnotation(SignatureSecured.class);
      if (signatureSecured != null)
      {
         registerSecurity(context, signatureSecured, signatureSecured.payloadType());
      }
   }
   
   private <T> void registerSecurity(FeatureContext context, SignatureSecured signatureSecured, Class<T> payloadType)
   {
      SignatureService<T> signatureService = getService(payloadType, signatureSecured.scopeId());
      context.register(new SignedObjectFilter<T>(signatureService, signatureSecured));
      ReaderInterceptor interceptor;
      if (signatureService.mayBeSelfSigned())
         interceptor = new SelfSignedObjectInterceptor<T>(signatureService, signatureSecured);
      else
         interceptor = new SignedObjectInterceptor<T>(signatureService, signatureSecured);
      context.register(interceptor);
   }
   
   private synchronized <T> SignatureService<T> getService(Class<T> payloadType, String scopeId)
   {
      @SuppressWarnings("unchecked")
      SignatureService<T> signatureService = (SignatureService<T>)signatureServices.get(new ClassAndId(payloadType, scopeId));
      Objects.requireNonNull(signatureService, "Unable to access SignatureService<id:"+scopeId+","+payloadType.getSimpleName()+">");
      return signatureService;
   }
}
