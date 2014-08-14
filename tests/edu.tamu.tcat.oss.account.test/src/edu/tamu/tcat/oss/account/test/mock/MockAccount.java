package edu.tamu.tcat.oss.account.test.mock;

import java.util.UUID;

import edu.tamu.tcat.account.Account;

public class MockAccount implements Account
{
   public String pid;
   public UUID uid;
   
   @Override
   public UUID getId()
   {
      return uid;
   }

   @Override
   public String getTitle()
   {
      return "mock";
   }

   @Override
   public boolean isActive()
   {
      return true;
   }
}
