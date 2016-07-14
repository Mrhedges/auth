package edu.tamu.tcat.account.db;

import java.util.function.Function;

import edu.tamu.tcat.account.token.AccountTokenException;
import edu.tamu.tcat.account.token.TokenService;

/**
 * Used to adapt tokens provided by one {@link TokenService} into tokens with a different
 * payload type. Typically the tokens managed by the source service encode data based on
 * a key value that can be used to lookup a referenced object of the desired payload type.
 * For example, this can be used to adapt a simple UUID-based token service and use the
 * tokenized UUID to lookup an associated account object. This allows a minimal data
 * representation to be transferred to the token bearer and ensures that the account
 * information returned by the token service reflects any local changes that have
 * been made since the token was issued.
 *
 * @param <PayloadType> The payload type that the underlying token representation will be
 *       adapted into/from.
 * @param <KeyType> The payload type of the underlying token scheme.
 */
public class AdaptingTokenService<PayloadType, KeyType> implements TokenService<PayloadType>
{
   private final Class<PayloadType> type;
   private final TokenService<KeyType> delegate;
   private final Function<PayloadType, KeyType> keyAdapter;
   private final Function<KeyType, PayloadType> itemResolver;

   /**
    * Construct a new {@link AdaptingTokenService} from a delegate {@link TokenService}.
    *
    * @param type The Java type of the target payload represented by this
    *       token service interface.
    * @param delegate The delegate {@code TokenService} that will be used to
    *       create and unpack tokens
    * @param keyAdapter A function that maps instances of the target payload type
    *       into instances of the key that can be processed by the delegate service.
    * @param itemResolver A function that maps instances of the key associated with
    *       the packed token data into an instance of the target payload.
    */
   public AdaptingTokenService(Class<PayloadType> type,
                               TokenService<KeyType> delegate,
                               Function<PayloadType, KeyType> keyAdapter,
                               Function<KeyType, PayloadType> itemResolver)
   {
      this.type = type;
      this.delegate = delegate;
      this.keyAdapter = keyAdapter;
      this.itemResolver = itemResolver;
   }

   @Override
   public TokenData<PayloadType> createTokenData(PayloadType item) throws AccountTokenException
   {
      KeyType key = keyAdapter.apply(item);
      TokenData<KeyType> token = delegate.createTokenData(key);
      return new AdaptedTokenData(token, item);
   }

   @Override
   public PayloadType unpackToken(String token) throws AccountTokenException
   {
      KeyType key = delegate.unpackToken(token);
      return itemResolver.apply(key);
   }

   @Override
   public Class<PayloadType> getPayloadType()
   {
      return type;
   }

   private class AdaptedTokenData implements TokenData<PayloadType>
   {
      private final TokenData<KeyType> delegate;
      private PayloadType item = null;

      private AdaptedTokenData(TokenData<KeyType> delegate, PayloadType data)
      {
         this.delegate = delegate;
         this.item = data;
      }

      @Override
      public PayloadType getPayload()
      {
         synchronized (this)
         {
            if (item == null)
               item = itemResolver.apply(delegate.getPayload());
         }

         return item;
      }

      @Override
      public String getToken()
      {
         return delegate.getToken();
      }

      @Override
      public String getExpireStr()
      {
         return delegate.getExpireStr();
      }
   }
}
