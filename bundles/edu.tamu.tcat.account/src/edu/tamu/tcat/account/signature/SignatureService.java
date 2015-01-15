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
package edu.tamu.tcat.account.signature;

import java.util.List;
import java.util.Map;

import edu.tamu.tcat.account.AccountException;

/**
 * An API for creating and unpacking signatures of a particular "payload type".
 * <p>
 * Implementations should be configured with the expiration time. Multiple {@link SignatureService}s
 * may be used within the same application.
 *
 * @param <PayloadType>
 */
public interface SignatureService<PayloadType>
{
   /**
    * Get a payload given the provided identifier.
    * @param identifier The identifier as provided by the request
    * @return A payload used to get public keys and check signatures.
    *          May return <code>null</code>.
    *          If identifier is formatted correctly but no account exists.  If {@link #mayBeSelfSigned()} returns <code>true</code>,
    *          this must return <code>null</code> over throwing for a non-existant account.
    * @throws SignatureException Thrown if the identifier is not in a valid format.
    * @throws AccountException Thrown if the payload cannot be fetched.
    */
   PayloadType getPayload(String identifier) throws SignatureException, AccountException;
   
   /**
    * Provide a Class representing {@code <PayloadType>}. This is used to validate this service can handle
    * type of payload available when both are retrieved anonymously.
    * 
    * @return The payload type. Does not return {@code null}
    */
   Class<PayloadType> getPayloadType();
   
   /**
    * Indicates if the payload may be self signed, in which case the public key may not be available until after the payload is processed
    * Only really useful is the payload contains an account-like object.
    * @return <code>true</code> if potentially self signed, <code>false</code> otherwise.
    */
   boolean mayBeSelfSigned();

   /**
    * Get a representation of security payload from the given request payload object.
    * Only really useful when {@link #mayBeSelfSigned()} return <code>true</code>.
    * @param result The request payload object after deserialization.
    * @return The payload.  May not be <code>null</code>.
    */
   PayloadType getSelfSigningPayload(Object result);
   
   /**
    * The scope used in the Authorization header.
    * The header is of the format:
    * Authorization: Scope: data
    * @return The authorization scope.  May not be <code>null</code>.
    */
   String getAuthorizationScope();
   
   /**
    * Get a request verifier from a given security payload object 
    * @param payload The security payload as returned by {@link #getPayload(String)} or {@link #getSelfSigningPayload(Object)}.
    * @param signature The signature in the authorization header.
    * @return A {@link Verifier} used to verify requests.
    */
   Verifier getVerifier(PayloadType account, byte[] signature);
   
   /**
    * Get a request verifier with a security payload to be provided later.
    * @param signature The signature in the authorization header.
    * @return A {@link SelfSignedVerifier} used to verify requests.
    */
   SelfSignedVerifier<PayloadType> getVerifier(byte[] signature);
   
   /**
    * An API for an object that is used to verify signatures.
    */
   interface Verifier
   {
      /**
       * Get a list of headers to add to signature content
       * @param headers The headers provided by the request.  This map is a copy and may be modified.
       * @return A {@link Map} of header names to values.  May not be <code>null</code>.
       */
      Map<String, List<String>> getSignedHeaders(Map<String,List<String>> headers);
      
      /**
       * Validate headers for any contraints, such as Date ranges.
       * @param method The HTTP method used, such as GET or PUT, etc..
       * @param headers The headers provided in the request.
       */
      void validateAdditionalHeaders(String method, Map<String,List<String>> headers);
      
      /**
       * Process signature bytes.
       * @param data The data to process
       * @throws SignatureException Thrown if the verifier cannot process the data.
       */
      void processSignedData(byte[] data) throws SignatureException;

      /**
       * Process signature bytes.
       * @param data The data to process
       * @param offset The offset in the data to process.
       * @param bytesToRead The number of bytes to process.
       * @throws SignatureException Thrown if the verifier cannot process the data.
       */
      void processSignedData(byte[] data, int offset, int bytesToRead) throws SignatureException;

      /**
       * Verify the signature.  No futher operations will be performed on this verifier after this method
       * @return <code>true</code> if the signature is valid, <code>false</code> otherwise.
       * @throws SignatureException Thrown if the verifier cannot verify the signature.
       */
      boolean verify() throws SignatureException;
   }
   
   /**
    * A specialization of {@link Verifier} which is not initialized with the means of fetching
    * the public key used to verify signatures.  This is provided later via {@link #usePayload(Object)}.
    *
    * @param <PayloadType> The type of the payload expected.
    */
   interface SelfSignedVerifier<PayloadType> extends Verifier
   {
      /**
       * Sets the payload used to fetch the public key.  The verifier would not have the public key during initialization.
       * <p>
       * Note: {@link #processSignedData(byte[])} and {@link #processSignedData(byte[], int, int)} will be called before
       * this method.
       * @param payload The payload to returned by {@link SignatureService#getSelfSigningPayload(Object)}.
       */
      void usePayload(PayloadType payload);
   }
}
