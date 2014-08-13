package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import edu.tamu.tcat.account.token.TokenService;

public class MockTokenData implements TokenService.TokenData<UUID>
{
   private String token;
   private String expireStr;
   private UUID uuid;

   public MockTokenData(String t, UUID uuid, String expStr)
   {
      token = t;
      this.uuid = uuid;
      expireStr = expStr;
   }
   
   @Override
   public String getToken()
   {
      return token;
   }
   
   @Override
   public UUID getPayload()
   {
      return uuid;
   }

   @Deprecated
   @Override
   public String getExpireStr()
   {
      return expireStr;
   }
}