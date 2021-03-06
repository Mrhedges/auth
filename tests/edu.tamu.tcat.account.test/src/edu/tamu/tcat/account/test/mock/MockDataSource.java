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

import java.sql.SQLException;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;

import edu.tamu.tcat.db.postgresql.PostgreSqlDataSourceFactory;
import edu.tamu.tcat.db.postgresql.PostgreSqlPropertiesBuilder;
import edu.tamu.tcat.db.provider.DataSourceProvider;
import edu.tamu.tcat.osgi.config.ConfigurationProperties;

public class MockDataSource implements DataSourceProvider
{
   public static final Logger DB_LOGGER = Logger.getLogger("edu.tamu.tcat.oss.db.hsqldb");

   public static final String PROP_URL = "db.postgres.url";
   public static final String PROP_USER = "db.postgres.user";
   public static final String PROP_PASS = "db.postgres.pass";

   public static final String PROP_MAX_ACTIVE = "db.postgres.active.max";
   public static final String PROP_MAX_IDLE = "db.postgres.idle.max";
   public static final String PROP_MIN_IDLE = "db.postgres.idle.min";
   public static final String PROP_MIN_EVICTION = "db.postgres.eviction.min";
   public static final String PROP_BETWEEN_EVICTION = "db.postgres.eviction.between";

   private ExecutorService executor;
   private DataSource dataSource;
   private ConfigurationProperties props;
   
   public MockDataSource()
   {
      // TODO Auto-generated constructor stub
   }

   public void bind(ConfigurationProperties cp)
   {
      this.props = cp;
   }

   private static int getIntValue(ConfigurationProperties props, String prop, int defaultValue)
   {
      Integer d = Integer.valueOf(defaultValue);
      Integer result = props.getPropertyValue(prop, Integer.class, d);

      return result.intValue();
   }

   // called by OSGi DS
   public void activate()
   {
      try
      {
   
         String url = props.getPropertyValue(PROP_URL, String.class);
         String user = props.getPropertyValue(PROP_USER, String.class);
         String pass = props.getPropertyValue(PROP_PASS, String.class);
   
         Objects.requireNonNull(url, "Database connection URL not supplied");
         Objects.requireNonNull(user, "Database username not supplied");
         Objects.requireNonNull(pass, "Database password not supplied");
   
         int maxActive = getIntValue(props, PROP_MAX_ACTIVE, 30);
         int maxIdle = getIntValue(props, PROP_MAX_IDLE, 3);
         int minIdle = getIntValue(props, PROP_MIN_IDLE, 0);
         int minEviction = getIntValue(props, PROP_MIN_EVICTION, 10 * 1000);
         int betweenEviction = getIntValue(props, PROP_BETWEEN_EVICTION, 100);
         
         PostgreSqlDataSourceFactory factory = new PostgreSqlDataSourceFactory();
         PostgreSqlPropertiesBuilder builder = factory.getPropertiesBuilder().create(url, user, pass);
         dataSource = factory.getDataSource(builder.getProperties());
         
         //HACK: should add this API to the properties builder instead of downcasting and overriding
         {
            BasicDataSource basic = (BasicDataSource)dataSource;
            
            basic.setMaxActive(maxActive);
            basic.setMaxIdle(maxIdle);
            basic.setMinIdle(minIdle);
            basic.setMinEvictableIdleTimeMillis(minEviction);
            basic.setTimeBetweenEvictionRunsMillis(betweenEviction);
         }

         this.executor = Executors.newSingleThreadExecutor();
      }
      catch (Exception e)
      {
         throw new IllegalStateException("Failed initializing data source", e);
      }
   }

   public void dispose()
   {
      if (executor != null)
      {
         boolean terminated = false;
         try
         {
            executor.shutdown();
            terminated = executor.awaitTermination(30, TimeUnit.SECONDS);
         }
         catch (InterruptedException e)
         {
            terminated = false;
         }

         if (!terminated)
         {
            DB_LOGGER.log(Level.SEVERE, "DBExecutor failed to complete all tasks.");
            executor.shutdownNow();
         }
      }
   }
   
   @Override
   public DataSource getDataSource() throws SQLException
   {
      return dataSource;
   }
}
