/*
 * Copyright 2014 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.tamu.tcat.account.test.mock;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import edu.tamu.tcat.account.test.CryptoUtil;
import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.TokenException;

public class MockEncryptingUuidTokenService implements TokenService<UUID>
{
   final String keyb64_128 = "blahDiddlyBlahSchmacko";
   final String keyb64_256 = "blahDiddlyBlahSchmackety+ABitLongerThanThat+";
   private final SecureToken secureToken;
   
   public MockEncryptingUuidTokenService() throws AccountTokenException
   {
      this(CryptoUtil.getProvider());
   }
   
   public MockEncryptingUuidTokenService(CryptoProvider cryptoProvider) throws AccountTokenException
   {
      byte[] key;
      try
      {
         key = Base64.getDecoder().decode(keyb64_128);
      }
      catch (Exception e)
      {
         throw new AccountTokenException("Could not decode token key", e);
      }
      try
      {
         secureToken = cryptoProvider.getSecureToken(key);
      }
      catch (Exception e)
      {
         throw new AccountTokenException("Could not construct secure token", e);
      }
   }
   
   @Override
   public TokenService.TokenData<UUID> createTokenData(UUID id) throws AccountTokenException
   {
      ByteBuffer buffer = ByteBuffer.allocate(4 + 8 + 16);
      ZonedDateTime now = ZonedDateTime.now();
      ZonedDateTime expires = now.plus(2, ChronoUnit.WEEKS);
      buffer.putInt(1);
      buffer.putLong(Instant.from(expires).toEpochMilli());
      buffer.putLong(id.getMostSignificantBits());
      buffer.putLong(id.getLeastSignificantBits());
      buffer.flip();
      try
      {
         String stok = secureToken.getToken(buffer);
         String exp = DateTimeFormatter.ISO_ZONED_DATE_TIME.format(expires);
         return new MockTokenData(stok, id, exp);
      }
      catch (TokenException e)
      {
         throw new AccountTokenException("Could not create token", e);
      }
   }
   
   @Override
   public UUID unpackToken(String token) throws AccountTokenException
   {
      return UUID.fromString(token);
   }
   
   @Override
   public Class<UUID> getPayloadType()
   {
      return UUID.class;
   }
}