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
package edu.tamu.tcat.oss.account.test;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.bouncycastle.BouncyCastleCryptoProvider;

// This is needed to do crypto stuff.
//HACK: this class is hack-ish.. should be exposed as a service
/** @deprecated These utilities should be exposed more locally to where they are needed */
@Deprecated
public final class CryptoUtil
{
   public static boolean authenticate(String passwordRaw, String passwordHashed)
   {
      return authenticate(getProvider(), passwordRaw, passwordHashed);
   }
   
   public static boolean authenticate(CryptoProvider cp, String passwordRaw, String passwordHashed)
   {
      if (passwordHashed == null)
         //TODO: log: "User ["+username+"] has no stored credential"
         return false;
      PBKDF2 pbkdf2Impl = cp.getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.checkHash(passwordRaw, passwordHashed);
   }
   
   public static String getHash(String passwordRaw)
   {
      return getHash(getProvider(), passwordRaw);
   }
   
   public static String getHash(CryptoProvider cp, String passwordRaw)
   {
      PBKDF2 pbkdf2Impl = cp.getPbkdf2(DigestType.SHA1);
      return pbkdf2Impl.deriveHash(passwordRaw);
   }
   
   public static CryptoProvider getProvider()
   {
      return new BouncyCastleCryptoProvider();
   }
}
