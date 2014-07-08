/*******************************************************************************
 * Copyright © 2008-14, All Rights Reserved
 * Texas Center for Applied Technology
 * Texas A&M Engineering Experiment Station
 * The Texas A&M University System
 * College Station, Texas, USA 77843
 *
 * Proprietary information, not for redistribution.
 ******************************************************************************/
package edu.tamu.tcat.account.login;

import javax.security.auth.login.LoginContext;

import edu.tamu.tcat.account.Account;

/**
 * The entry point to the account login (authentication) framework. This type
 * represents a base that implementations must implement to provide a common
 * API. This framework is designed to wrap JAAS and work together with it, and to
 * leverage its good parts.
 * <p>
 * Instance are not thread-safe and intended for single use for the purpose of
 * logging in to a secured application. The {@link #login()} process provides a {@link LoginData}
 * which may be used to find an {@link Account}.
 * <p>
 * Specific implementations must be default-constructible but may require
 * implementation-specific initialization and configuration. One such implementation may
 * simply delegate to the JAAS authentication entry point (i.e. {@link LoginContext}),
 * and utilize its configuration and class-loading mechanisms.
 */
public interface LoginProvider
{
   LoginData login() throws AccountLoginException;
}
