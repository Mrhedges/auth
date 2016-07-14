package edu.tamu.tcat.account.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import java.util.stream.IntStream;

import org.junit.Before;
import org.junit.Test;

import edu.tamu.tcat.account.db.ExpiringTokenProvider;
import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.TokenService.TokenData;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.TokenException;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

public class ExpiringTokenServiceTest
{

   private SecureToken secureToken;

   @Before
   public void setup() throws TokenException
   {
      byte[] key = makeSecureKey(256);
      System.out.println("Using security key: " + Base64.getEncoder().encodeToString(key));

      CryptoProvider crypto = getCryptoProvider();
      secureToken = crypto.getSecureToken(key);
   }

   private byte[] makeSecureKey(int keySize)
   {
      if (!IntStream.of(128, 196, 256).anyMatch(k -> k == keySize))
         throw new IllegalArgumentException(MessageFormat.format("Invalid key size {0}. Require 128, 196 or 256 bit keys.", keySize));

      byte[] bytes = new byte[keySize / 8];
      new SecureRandom().nextBytes(bytes);

      return bytes;
//      return Base64.getEncoder().encodeToString(bytes);
   }

   private CryptoProvider getCryptoProvider()
   {
      return new BouncyCastleCryptoProvider();
   }

   @Test
   public void testLongExpiringTokenService() throws InterruptedException, AccountTokenException
   {
      TokenService<Long> svc = ExpiringTokenProvider.LongTokenProviderFactory.makeProvider(secureToken, 1, ChronoUnit.SECONDS);
      long id = 42;
      TokenData<Long> tokenDataA = svc.createTokenData(id);

      Long value = svc.unpackToken(tokenDataA.getToken());
      assertEquals("Did not recover input id.", id, value.longValue());

      Thread.sleep(1001);
      try
      {
         value = svc.unpackToken(tokenDataA.getToken());
         assertFalse("Failed to properly expire the token", true);
      }
      catch (AccountTokenException te)
      {
         // expected exception -- TODO provide more specific sub-class
      }
   }
   @Test
   public void testUuidExpiringTokenService() throws InterruptedException, AccountTokenException
   {
      TokenService<UUID> svc = ExpiringTokenProvider.UuidTokenProviderFactory.makeProvider(secureToken, 1, ChronoUnit.SECONDS);
      UUID id = UUID.randomUUID();
      TokenData<UUID> tokenDataA = svc.createTokenData(id);

      UUID value = svc.unpackToken(tokenDataA.getToken());
      assertEquals("Did not recover input id.", id, value);

      Thread.sleep(1001);
      try
      {
         value = svc.unpackToken(tokenDataA.getToken());
         assertFalse("Failed to properly expire the token", true);
      }
      catch (AccountTokenException te)
      {
         // expected exception -- TODO provide more specific sub-class
      }
   }

   @Test
   public void testStringExpiringTokenService() throws InterruptedException, AccountTokenException
   {
      TokenService<String> svc = ExpiringTokenProvider.StringTokenProviderFactory.makeProvider(secureToken, "UTF-8", 1, ChronoUnit.SECONDS);
      String id = "Hello World";
      // Instant expires = ExpiringTokenService.fromNow(1, ChronoUnit.SECONDS);
      TokenData<String> tokenDataA = svc.createTokenData(id);

      String value = svc.unpackToken(tokenDataA.getToken());
      assertEquals("Did not recover input id.", id, value);

      Thread.sleep(1001);
      try
      {
         value = svc.unpackToken(tokenDataA.getToken());
         assertFalse("Failed to properly expire the token", true);
      }
      catch (AccountTokenException te)
      {
         // expected exception -- TODO provide more specific sub-class
      }
   }
}
