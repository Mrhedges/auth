package edu.tamu.tcat.oss.account.test.mock;

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