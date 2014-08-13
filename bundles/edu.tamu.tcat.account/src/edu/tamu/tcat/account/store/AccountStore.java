package edu.tamu.tcat.account.store;

import java.util.UUID;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
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
    * @return The account for the given criteria. Does not return {@code null}
    * @throws AccountNotFoundException If no {@link Account} exists for the provided criteria
    * @throws AccountException If an internal exception occurs attempting an account lookup
    */
   Account lookup(LoginData loginData) throws AccountException;
   
   /**
    * Get the {@link Account} representing the provided account identifier {@link UUID}.
    * 
    * @param accountId The account's unique identifier
    * @return The account for the given id. Does not return {@code null}
    * @throws AccountNotFoundException If no {@link Account} exists for the provided identifier
    * @throws AccountException If an internal exception occurs attempting an account lookup
    */
   Account getAccount(UUID accountId) throws AccountException;
}
