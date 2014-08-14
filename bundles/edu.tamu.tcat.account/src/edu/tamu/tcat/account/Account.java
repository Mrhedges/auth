package edu.tamu.tcat.account;

import java.util.UUID;

public interface Account
{
   UUID getId();
   
   String getTitle();
   
   boolean isActive();
}
