package edu.tamu.tcat.account.store;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;

public interface AccountStore
{
   /**
    * Get the {@link Account} representing the provided user identifier within the
    * scope of the identified login provider.
    * 
    * @param loginProviderId The id of the login provider for which the user ID applies
    * @param loginProviderUserId The login provider's identifier for a user account
    * @return The account for the given criteria. Does not return {@code null}
    * @throws AccountNotFoundException If no {@link Account} exists for the provided criteria
    * @throws AccountException If an internal exception occurs attempting an account lookup
    */
   Account lookup(String loginProviderId, String loginProviderUserId) throws AccountException;
}
