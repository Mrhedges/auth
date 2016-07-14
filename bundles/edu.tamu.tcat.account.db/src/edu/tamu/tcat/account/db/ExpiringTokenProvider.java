package edu.tamu.tcat.account.db;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.function.Function;

import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.TokenException;

/**
 * A {@link TokenService} implementation that provides expiring tokens.
 *
 * @param <Payload>
 */
public class ExpiringTokenProvider<Payload> implements TokenService<Payload>
{
   private final SecureToken secureToken;
   private final Class<Payload> type;
   private final Function<Payload, byte[]> marshaller;
   private final Function<byte[], Payload> unmarshaller;
   private final long duration;
   private final ChronoUnit unit;

   /**
    * Constructs a new {@link ExpiringTokenProvider}.
    *
    * @param secureToken The token to be used to encrypt the data.
    * @param marshaller A function to convert payload data into a byte-stream for
    *       tokenization.
    * @param unmarshaller A function that will convert the byte-stream from a token
    *       into an instance of the payload type. Should throw an
    *       {@link IllegalArgumentException} if the supplied byte stream cannot be parsed.
    * @param duration The amount of type the supplied token should be valid for.
    * @param unit The time units of duration.
    * @param type A Java class indicating the payload type.
    */
   public ExpiringTokenProvider(SecureToken secureToken,
                                Function<Payload, byte[]> marshaller,
                                Function<byte[], Payload> unmarshaller,
                                long duration, ChronoUnit unit, Class<Payload> type)
   {
      this.secureToken = secureToken;
      this.marshaller = marshaller;
      this.unmarshaller = unmarshaller;
      this.duration = duration;
      this.unit = unit;
      this.type = type;
   }

   @Override
   public TokenService.TokenData<Payload> createTokenData(Payload payload) throws AccountTokenException
   {
      return createTokenData(payload, fromNow(duration, unit));
   }

   public static Instant fromNow(long duration, ChronoUnit unit)
   {
      return Instant.now().plus(duration, unit);
   }

   public TokenService.TokenData<Payload> createTokenData(Payload payload, Instant expires) throws AccountTokenException
   {
      byte[] bytes = marshaller.apply(payload);
      ByteBuffer buffer = ByteBuffer.allocate(4 + 8 + bytes.length);

      buffer.putInt(1);
      buffer.putLong(expires.toEpochMilli());
      buffer.put(bytes);
      buffer.flip();
      try
      {
         String stok = secureToken.getToken(buffer);
         String exp = DateTimeFormatter.ISO_INSTANT.format(expires);
         return new AccountTokenData<>(stok, payload, exp);
      }
      catch (TokenException e)
      {
         throw new AccountTokenException("Could not create token", e);
      }
   }

   @Override
   public Payload unpackToken(String token) throws AccountTokenException
   {
      ByteBuffer buffer;
      try
      {
         buffer = secureToken.getContentFromToken(token);
      }
      catch (TokenException ex)
      {
         throw new AccountTokenException("Failed to parse the supplied token.", ex);
      }

      @SuppressWarnings("unused")
      int one = buffer.getInt();
      long epochMilli = buffer.getLong();
//      ZonedDateTime expires = ZonedDateTime.from(Instant.ofEpochMilli(epochMilli));
//      Instant.now().isAfter(Instant.ofEpochMilli(epochMilli))
      if (Instant.now().isAfter(Instant.ofEpochMilli(epochMilli)))
         throw new AccountTokenException("The supplied token has expired.");

      byte[] data = new byte[buffer.remaining()];
      buffer.get(data);
      return unmarshaller.apply(data);
   }

   @Override
   public Class<Payload> getPayloadType()
   {
      return type;
   }

   public static class UuidTokenProviderFactory
   {
      private static byte[] toByteArray(UUID value)
      {
         ByteBuffer buffer = ByteBuffer.allocate(16);
         buffer.putLong(value.getMostSignificantBits());
         buffer.putLong(value.getLeastSignificantBits());
         return buffer.array();
      }

      private static UUID toUuid(byte[] bytes)
      {
         ByteBuffer buffer = ByteBuffer.wrap(bytes);
         return new UUID(buffer.getLong(), buffer.getLong());
      }

      public static TokenService<UUID> makeProvider(SecureToken token, long duration, ChronoUnit unit)
      {
         return new ExpiringTokenProvider<>(token,
               UuidTokenProviderFactory::toByteArray,
               UuidTokenProviderFactory::toUuid,
               duration, unit, UUID.class);
      }
   }

   public static class LongTokenProviderFactory
   {
      private static byte[] toByteArray(long value)
      {
         ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
         buffer.putLong(value);
         return buffer.array();
      }

      private static long toLong(byte[] bytes)
      {
         ByteBuffer buffer = ByteBuffer.wrap(bytes);
         return buffer.getLong();
      }

      public static TokenService<Long> makeProvider(SecureToken token, long duration, ChronoUnit unit)
      {
         return new ExpiringTokenProvider<>(token,
               LongTokenProviderFactory::toByteArray,
               LongTokenProviderFactory::toLong,
               duration, unit, Long.class);
      }
   }

   public static class StringTokenProviderFactory
   {
      private static byte[] toByteArray(String value, String encoding)
      {
         try  {
            return value.getBytes(encoding);
         } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Invalid encoding: " + encoding, e);
         }
      }

      private static String toString(byte[] bytes, String encoding)
      {
         try {
            return new String(bytes, encoding);
         } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Invalid encoding: " + encoding, e);
         }
      }

      public static ExpiringTokenProvider<String> makeProvider(SecureToken token, long duration, ChronoUnit unit)
      {
         return makeProvider(token, "UTF-8", duration, unit);
      }

      public static ExpiringTokenProvider<String> makeProvider(SecureToken token, String encoding, long duration, ChronoUnit unit)
      {
         return new ExpiringTokenProvider<>(token,
               value -> toByteArray(value, encoding),
               bytes -> toString(bytes, encoding),
               duration, unit, String.class);
      }

   }

   private static class AccountTokenData<PT> implements TokenService.TokenData<PT>
   {
      private String token;
      private String expireStr;
      private PT data;

      public AccountTokenData(String t, PT data, String expStr)
      {
         this.token = t;
         this.data = data;
         this.expireStr = expStr;
      }

      @Override
      public String getToken()
      {
         return token;
      }

      @Override
      public PT getPayload()
      {
         return data;
      }

      @Override
      public String getExpireStr()
      {
         return expireStr;
      }
   }
}
