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
package edu.tamu.tcat.account;

import java.util.UUID;

/**
 * A representation of an entity that can be authenticated by the system such as a user,
 * organization, software agent, or other actor. An account is a minimalist entity that serves
 * to identify the account and carry information critical to use within any application. It
 * does not carry any additional details that are application-specific. That information should
 * be provided by an application-specific account data store.
 *
 * <p>An account is intended to be a lightweight data structure for use in virtually any
 * application that needs the notion of a user account. Accounts correspond 1:1 to a UUID to
 * allow simple mapping and lookups, and to allow the UUID to be serialized in place of an
 * account for network transactions and Account Data persistence.
 *
 * <p>To use an application, the user must have an Account within the scope of that
 * application. The simple case of this is that the application's data store has a list of
 * all user accounts, and the user selects the account on login. The account selection process
 * is typically done by the user entering credentials for a known authentication provider,
 * the application validating the credentials with that provider, and then looking up in a
 * mapping what account the credentials apply to. This mapping may be done automatically in
 * some cases, or the account may be created by the application if credential validation is
 * successful to ease the maintenance of separate accounts from authentication system
 * credentials.
 *
 * <p>The rationale of requiring an account known to the application is founded in the ability
 * of application administrators to have control over user accounts. App admins can disable
 * or delete accounts, removing the user's ability to log in or all traces of their history
 * with the application, but only if accounts are not implicitly tied to some external
 * system. Applications must also be able to store information associated with credentials
 * stored in systems that are not mutable by the application and should not maintain storage
 * of the credentials themselves. To store information associated with an account, an
 * application must be able to uniquely identify the account (via credentials) and map that
 * identifier to the storage area.
 *
 * <p>An account has the following fields:
 * <ul>
 *   <li>UUID</li>
 *   <li>display name</li>
 *   <li>is-active</li>
 * </ul>
 *
 * <p>These fields are not exhaustive of all application use, but are the baseline.
 *
 * <p>An inactive Account is one that cannot be authorized to act in the system (that is, it
 * is not allowed log in or to act on any of the roles or permissions that it has been
 * assigned) but it can be re-activated. This might happen, for example, to disable an account
 * for failure to pay or abide by system policies, to lock an account that requires a
 * password reset or to temporarily disable a group.
 *
 * <p>Certain systems may have a notion of a "deleted" account which is not expunged from the
 * database with access control maintained by the Account Store. In this case, a deleted
 * account is one that cannot be authorized to act and cannot be restored by the
 * system (through normal operations). By flagging accounts as deleted (rather than simply
 * removing them) the system retains historical information that may be useful for audit
 * history, data integrity or learning about user preferences and behavior. With respect to
 * 'normal' use of the system, a deleted account does not exist. The Account Store may
 * provide accessors for deleted accounts in API beyond that which is required by the framework.
 */
public interface Account
{
   /**
    * A globally unique identifier for this account. This is the primary encapsulated and
    * exportable identifier.
    *
    * @return The account id.
    */
   UUID getId();

   /**
    * Get a display name for the account, which is often a "user name" but not typically a
    * person's name.
    * @since 2.0
    */
   String getDisplayName();

   /**
    * Indicates whether this account is currently active within the system. Note that it is
    * common to require access to account information (for example for historical purposes or
    * within audit trails). Application-specific account data may provide additional detail
    * about the reason an account is no longer active and guide application-specific controls
    * over whether that account can be re-activated.
    *
    * <p>Note that the account status is independent from the login method. For example, a
    * particular authentication mechanism may be restricted due to too many failed attempts
    * or permissions being revoked from a third-party authority such as Facebook without
    * affecting the active/inactive status of the account.
    *
    * @return {@code true} if this account is active.
    */
   boolean isActive();
}
