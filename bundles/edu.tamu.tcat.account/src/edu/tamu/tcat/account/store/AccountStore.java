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
package edu.tamu.tcat.account.store;

import java.util.UUID;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;

public interface AccountStore
{
   /**
    * Look up the authenticated {@link Account} representing the provided user information within the
    * scope of a login provider as defined by the provided {@link LoginData}.
    * <p>
    * This is invoked after authentication has already been performed against a {@link LoginProvider}
    * which has provided a {@link LoginData}, containing the parameters needed to look up an account.
    *
    * @param loginData Information about an authenticated user
    * @return The account for the given criteria or {@code null} if none found.
    */
   Account lookup(LoginData loginData);

   /**
    * Get the {@link Account} representing the provided account identifier {@link UUID}.
    *
    * @param accountId The account's unique identifier
    * @return The account for the given id or {@code null} if none found.
    */
   Account getAccount(UUID accountId);
}
