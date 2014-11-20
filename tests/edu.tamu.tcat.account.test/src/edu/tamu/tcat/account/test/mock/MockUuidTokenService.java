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

import java.util.UUID;

import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;

public class MockUuidTokenService implements TokenService<UUID>
{
   @Override
   public TokenService.TokenData<UUID> createTokenData(UUID uuid) throws AccountTokenException
   {
      return new MockTokenData(uuid.toString(), uuid, "Expires eventually");
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