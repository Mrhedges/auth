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

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.store.AccountStore;

public class MockAccountStore implements AccountStore
{
   @Override
   public Account lookup(LoginData loginData) throws AccountException
   {
      MockAccount acct = new MockAccount();
      acct.pid = loginData.getLoginUserId();
      acct.uid = UUID.randomUUID();
      return acct;
   }

   @Override
   public Account getAccount(UUID accountId) throws AccountException
   {
      MockAccount acct = new MockAccount();
      acct.pid = "mock.user."+accountId.toString();
      acct.uid = accountId;
      return acct;
   }
}