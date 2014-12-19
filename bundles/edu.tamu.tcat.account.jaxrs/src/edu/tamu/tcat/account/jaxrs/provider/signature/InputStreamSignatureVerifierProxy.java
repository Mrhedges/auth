package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.IOException;
import java.io.InputStream;

import edu.tamu.tcat.account.signature.SignatureException;
import edu.tamu.tcat.account.signature.SignatureService.Verifier;

public class InputStreamSignatureVerifierProxy extends InputStream
{
   private final InputStream proxy;
   private final Verifier verifier;
   
   public InputStreamSignatureVerifierProxy(InputStream proxy, Verifier verifier)
   {
      this.proxy = proxy;
      this.verifier = verifier;
   }
   
   @Override
   public int read() throws IOException
   {
      int value = proxy.read();
      if (value > -1)
      {
         try
         {
            verifier.processSignedData(new byte[]{(byte)value});
         }
         catch (SignatureException e)
         {
            throw new IOException(e);
         }
      }
      return value;
   }
   
   @Override
   public int read(byte[] b, int off, int len) throws IOException
   {
      int bytesRead = proxy.read(b, off, len);
      if (bytesRead > 0)
      {
         try
         {
            verifier.processSignedData(b, off, bytesRead);
         }
         catch (SignatureException e)
         {
            throw new IOException(e);
         }
      }
      return bytesRead;
   }
   
   @Override
   public long skip(long n) throws IOException
   {
      throw new UnsupportedOperationException("Skipping bytes interferes with signature");
   }
   
   @Override
   public int available() throws IOException
   {
      return proxy.available();
   }
   
   @Override
   public void close() throws IOException
   {
      proxy.close();
   }
   
   @Override
   public synchronized void mark(int readlimit)
   {
      throw new UnsupportedOperationException("Marking interferes with signature");
   }
   
   @Override
   public synchronized void reset() throws IOException
   {
      throw new UnsupportedOperationException("Reseting interferes with signature");
   }
   
   @Override
   public boolean markSupported()
   {
      return false;
   }
}
