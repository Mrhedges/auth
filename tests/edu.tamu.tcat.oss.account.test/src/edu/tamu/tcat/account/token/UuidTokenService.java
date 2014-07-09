package edu.tamu.tcat.account.token;

import java.util.UUID;

/**
 * A {@link TokenService} which uses {@link UUID} data as its payload.
 */
public interface UuidTokenService extends TokenService<UUID>
{
   // tag interface to be used where generics are not friendly
}
