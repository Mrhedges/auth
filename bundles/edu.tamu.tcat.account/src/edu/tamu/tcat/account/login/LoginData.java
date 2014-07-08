package edu.tamu.tcat.account.login;

import java.security.Principal;

import edu.tamu.tcat.account.Account;
import edu.tamu.tcat.account.AccountException;

/**
 * A data vehicle used to represent and encapsulate data from a user's account on an authentication
 * provider, defined by a {@link LoginProvider}. Each login provider implementation may connect to
 * some external service to perform authentication and may provide some arbitrary data back. In
 * JAAS, this data is represented by {@link Principal}s.
 */
public interface LoginData
{
   /**
    * @return The app-defined identifier for the {@link LoginProvider} which provided
    *         this data.
    */
   String getLoginProviderId();
   
   /**
    * Get an identifier representing the user account authenticated by the {@link LoginProvider}.
    * The identifier must be unique only within the scope of the login provider instance, defined
    * by {@link #getLoginProviderId()}. This identifier is used to match an {@link Account} to
    * this LoginData.
    * 
    * @return The identifier for the authenticated account.
    */
   String getLoginUserId();
   
   /**
    * Access data provided by the {@link LoginProvider}. The keys used are defined by
    * the login provider's implementation and configuration. Values may be accessed by
    * type, and this instance is free to attempt type conversion as it is able to provide
    * the requested data as the requested type.
    * 
    * @param key The data entry requested. Must not be {@code null}.
    * @param type The requested type of data. May be {@code null} to access unknown data as type Object.
    * @return The data element, or {@code null} if the value is {@code null}. Implementations may choose to return
    *         {@code null} if the requested key is not known, but this is not recommended since the caller cannot
    *         distinguish an invalid key from a missing value.
    * @throws AccountException If the key is not known or the value cannot be resolved to the requested type.
    */
   <T> T getData(String key, Class<T> type) throws AccountException;
}
