/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.auth.signatures;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility for Elliptic Curve keys.
 */
public enum EC {
    ;

    private static final String EC = "EC";
    private static final String SUNEC = "SunEC"; // Sun's ECC provider

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    public static PrivateKey privateKeyFromPKCS8(final byte[] pkcs8) throws InvalidKeySpecException {
        try {
            final EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pkcs8);
            final KeyFactory keyFactory = KeyFactory.getInstance(EC, SUNEC);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a public key constructed from the given DER bytes.
     */
    public static PublicKey publicKeyFrom(final byte[] derBytes) throws InvalidKeySpecException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(EC, SUNEC);
            final EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(derBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }
}
