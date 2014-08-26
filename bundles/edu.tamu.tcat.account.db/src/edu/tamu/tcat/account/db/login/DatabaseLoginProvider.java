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
package edu.tamu.tcat.account.db.login;

import edu.tamu.tcat.account.db.internal.DatabaseAuthUtil;
import edu.tamu.tcat.account.db.spi.DatabaseLoginModule;
import edu.tamu.tcat.account.login.AccountLoginException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.login.LoginProvider;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.db.exec.sql.SqlExecutor;

/**
 * An implementation of a {@link LoginProvider} which performs authentication against a database.
 * 
 * @see {@link DatabaseLoginModule} for an implementation of {@link javax.security.auth.spi.LoginModule} backed by a database.
 */
public class DatabaseLoginProvider implements LoginProvider
{
   private String userName;
   private String pass;
   private String instanceId;
   private CryptoProvider crypto;
   private SqlExecutor exec;

   public void init(String providerId, String username, String password, CryptoProvider cp, SqlExecutor dbExec)
   {
      this.instanceId = providerId;
      this.userName = username;
      this.pass = password;
      this.crypto = cp;
      this.exec = dbExec;
   }

   @Override
   public LoginData login() throws AccountLoginException
   {
      try
      {
         DatabaseAuthUtil.AccountRecord rec = DatabaseAuthUtil.getRecord(crypto, exec, userName, pass);
         LoginData rv = new DatabaseAuthUtil.DbLoginData(instanceId, rec);
         return rv;
      }
      catch (Exception e)
      {
         throw new AccountLoginException(e);
      }
   }
}
