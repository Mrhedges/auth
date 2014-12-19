package edu.tamu.tcat.account.jaxrs.provider.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class InputStreamByteArrayProxy extends InputStream
{
   private final InputStream proxy;
   private final ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();
   
   public InputStreamByteArrayProxy(InputStream proxy)
   {
      this.proxy = proxy;
   }
   
   public InputStreamByteArrayProxy(InputStream proxy, byte[] startData) throws IOException
   {
      this.proxy = proxy;
      byteArrayStream.write(startData);
   }
   
   public byte[] getBytes()
   {
      return byteArrayStream.toByteArray();
   }
   
   @Override
   public int read() throws IOException
   {
      int value = proxy.read();
      if (value > -1)
         byteArrayStream.write(value);
      return value;
   }
   
   @Override
   public int read(byte[] b, int off, int len) throws IOException
   {
      int bytesRead = proxy.read(b, off, len);
      if (bytesRead > 0)
         byteArrayStream.write(b, off, bytesRead);
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
      byteArrayStream.close();
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
