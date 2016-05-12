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
package edu.tamu.tcat.account.db.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;
import edu.tamu.tcat.account.login.LoginData;
import edu.tamu.tcat.account.store.AccountNotFoundException;
import edu.tamu.tcat.account.store.AccountStore;
import edu.tamu.tcat.db.exec.sql.SqlExecutor;

/**
 * An implementation of {@link AccountStore} backed by a database. Uses this table definition to store accounts:
 * <pre>
 * CREATE TABLE account
 * (
 *   id bigserial NOT NULL,
 *   account_id text NOT NULL,
 *   title text NOT NULL,
 *   account_type text NOT NULL,
 *   is_active boolean,
 *   is_deleted boolean,
 *   CONSTRAINT id PRIMARY KEY (id)
 * )
 * </pre>
 *
 * Where:
 * <ul><li><em>id</em> is a per-record identifier</li>
 *     <li><em>account_id</em> is the string form of a {@link UUID} (unique)</li>
 *     <li><em>title</em> is a short display string for the account, such as a user-display-id (not unique)</li>
 *     <li><em>account_type</em> is a string for "user", "group", or "role"</li>
 *     <li><em>is_active</em> is used to disable login</li>
 *     <li><em>is_deleted</em> is used to disable account access but keep the record in the
 *         database for auditing purposes, and is never exposed</li>
 * </ul>
 */
public class DatabaseAccountStore implements AccountStore
{
   static class DatabaseAccount implements Account
   {
      public long id;
      public UUID uuid;
      public String title;
      public String type;
      public boolean isActive;

      public DatabaseAccount()
      {
      }

      @Override
      public UUID getId()
      {
         return uuid;
      }

      @Override
      public String getTitle()
      {
         return title;
      }

      public String getType()
      {
         return type;
      }

      @Override
      public boolean isActive()
      {
         return isActive;
      }
   }

   private SqlExecutor dbExec;

   public void bind(SqlExecutor db)
   {
      dbExec = db;
   }

   /*
    * Table "account": stores accounts, groups, and roles
    * Table "account_authn": maps accounts that can log in to login provider and login-provider-user-id
    * Table "authn_local": is a "local db" authn provider using "long" for user-id
    *
    * TODO: create groups for "everyone" and "debug"
    * TODO: link accounts to local auth in account_authn
    */

   @Override
   public Account lookup(LoginData loginData) throws AccountException
   {
      Objects.requireNonNull(loginData, "Login data may not be null");
      final String pid = loginData.getLoginProviderId();
      if (pid == null || pid.trim().isEmpty())
         throw new IllegalArgumentException("Login data provider id may not be empty");
      final String puid = loginData.getLoginUserId();
      if (puid == null || puid.trim().isEmpty())
         throw new IllegalArgumentException("Login data provider user id may not be empty");

      SqlExecutor.ExecutorTask<DatabaseAccount> task = new SqlExecutor.ExecutorTask<DatabaseAccount>()
      {
         @Override
         public DatabaseAccount execute(Connection conn) throws Exception
         {
            UUID uuid = null;

            String sql = "SELECT account_id FROM account_authn WHERE auth_provider_user_id = ? AND auth_provider_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql))
            {
               ps.setString(1, puid);
               ps.setString(2, pid);

               try (ResultSet rs = ps.executeQuery())
               {
                  if (!rs.next())
                     throw new AccountNotFoundException("No mapping exists for provider ["+pid+"] and user ["+puid+"]");

                  String uuidStr = rs.getString("account_id");
                  if (uuidStr == null || uuidStr.trim().isEmpty())
                     throw new IllegalStateException("Mapping for provider ["+pid+"] and user ["+puid+"] has missing account id");

                  try
                  {
                     uuid = UUID.fromString(uuidStr);
                  }
                  catch (Exception e)
                  {
                     throw new IllegalStateException("Mapping for provider ["+pid+"] and user ["+puid+"] has invalid account UUID ["+uuidStr+"]");
                  }
               }
            }

            // Have a valid UUID, now find the account data for it
            // This could be done with a join and more efficient query, but it may be helpful to have the extra logging
            sql = "SELECT * FROM account WHERE account_id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql))
            {
               ps.setString(1, uuid.toString());

               try (ResultSet rs = ps.executeQuery())
               {
                  if (!rs.next())
                     throw new AccountNotFoundException("No account exists for id ["+uuid+"] from provider ["+pid+"] and user ["+puid+"]");

                  if (rs.getBoolean("is_deleted"))
                     throw new AccountNotFoundException("Cannot retrieve deleted account ["+uuid+"] from provider ["+pid+"] and user ["+puid+"]");

                  DatabaseAccount rv = new DatabaseAccount();
                  rv.id = rs.getLong("id");
                  rv.uuid = uuid;
                  rv.title = rs.getString("title");
                  // For now, all accounts are "user"
                  //rv.type = rs.getString("type");
                  rv.isActive = rs.getBoolean("is_active");

                  return rv;
               }
            }
         }
      };

      try
      {
         Future<DatabaseAccount> f = dbExec.submit(task);
         // Store the data in fields to be used in commit()
         DatabaseAccount rec = f.get(10, TimeUnit.SECONDS);
         return rec;
      }
      catch (Exception e)
      {
         throw new AccountException("Failed database processing", e);
      }
   }

   @Override
   public Account getAccount(UUID accountId) throws AccountException
   {
      // TODO Auto-generated method stub
      return null;
   }

   public Account createAccount(String title) throws AccountException
   {
      if (title == null || title.trim().isEmpty())
         throw new IllegalArgumentException("Account title may not be empty");

      DatabaseAccount newAcct = new DatabaseAccount();
      newAcct.uuid = UUID.randomUUID();
      newAcct.title = title;
      newAcct.type = "user";

      final AtomicReference<DatabaseAccount> ref = new AtomicReference<>(newAcct);

      SqlExecutor.ExecutorTask<DatabaseAccount> task = new SqlExecutor.ExecutorTask<DatabaseAccount>()
      {
         @Override
         public DatabaseAccount execute(Connection conn) throws Exception
         {
            DatabaseAccount acct = ref.get();

            String sql = "INSERT INTO account (account_id, title, account_type, is_active, is_deleted) VALUES (?,?,?,?,?)";
            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS))
            {
               ps.setString(1, acct.uuid.toString());
               ps.setString(2, acct.title);
               ps.setString(3, acct.type);
               ps.setBoolean(4, false); // new accounts are not active
               ps.setBoolean(5, false); // new accounts are not deleted

               ps.execute();
               try (ResultSet rs = ps.getGeneratedKeys())
               {
                  if (!rs.next())
                     throw new IllegalStateException("Failed sql insert providing new key");

                  acct.id = rs.getLong("id");
               }

               ref.set(acct);
               return acct;
            }
         }
      };

      try
      {
         Future<? extends Account> f = dbExec.submit(task);
         // Store the data in fields to be used in commit()
         Account rec = f.get(10, TimeUnit.SECONDS);
         return rec;
      }
      catch (Exception e)
      {
         throw new AccountException("Failed database processing", e);
      }
   }
}
