package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;
import edu.tamu.tcat.account.token.uuid.UuidTokenService;

public class MockUuidTokenService implements UuidTokenService
{
   @Override
   public TokenService.TokenData<UUID> createTokenData(UUID uuid, long expiresIn, TimeUnit expiresInUnit) throws AccountTokenException
   {
      return new MockTokenData(uuid.toString(), uuid, String.valueOf(expiresIn) + "." + expiresInUnit.toString());
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