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

import org.junit.Assert;
import org.junit.Test;

import static org.tomitribe.auth.signatures.Algorithm.*;

public class AlgorithmTest extends Assert {

    @Test
    public void portableName() throws Exception {
        assertEquals("hmac-sha1", HMAC_SHA1.getPortableName());
        assertEquals("hmac-sha224", HMAC_SHA224.getPortableName());
        assertEquals("hmac-sha256", HMAC_SHA256.getPortableName());
        assertEquals("hmac-sha384", HMAC_SHA384.getPortableName());
        assertEquals("hmac-sha512", HMAC_SHA512.getPortableName());
        assertEquals("rsa-sha1", RSA_SHA1.getPortableName());
        assertEquals("rsa-sha256", RSA_SHA256.getPortableName());
        assertEquals("rsa-sha384", RSA_SHA384.getPortableName());
        assertEquals("rsa-sha512", RSA_SHA512.getPortableName());
        assertEquals("dsa-sha1", DSA_SHA1.getPortableName());
        assertEquals("dsa-sha224", DSA_SHA224.getPortableName());
        assertEquals("dsa-sha256", DSA_SHA256.getPortableName());
        assertEquals("ecdsa-sha1", ECDSA_SHA1.getPortableName());
        assertEquals("ecdsa-sha256", ECDSA_SHA256.getPortableName());
        assertEquals("ecdsa-sha384", ECDSA_SHA384.getPortableName());
        assertEquals("ecdsa-sha512", ECDSA_SHA512.getPortableName());
    }

    @Test
    public void jvmNames() {
        assertEquals("HmacSHA1", HMAC_SHA1.getJvmName());
        assertEquals("HmacSHA224", HMAC_SHA224.getJvmName());
        assertEquals("HmacSHA256", HMAC_SHA256.getJvmName());
        assertEquals("HmacSHA384", HMAC_SHA384.getJvmName());
        assertEquals("HmacSHA512", HMAC_SHA512.getJvmName());
        assertEquals("SHA1withRSA", RSA_SHA1.getJvmName());
        assertEquals("SHA256withRSA", RSA_SHA256.getJvmName());
        assertEquals("SHA384withRSA", RSA_SHA384.getJvmName());
        assertEquals("SHA512withRSA", RSA_SHA512.getJvmName());
        assertEquals("SHA1withDSA", DSA_SHA1.getJvmName());
        assertEquals("SHA224withDSA", DSA_SHA224.getJvmName());
        assertEquals("SHA256withDSA", DSA_SHA256.getJvmName());
        assertEquals("SHA1withECDSA", ECDSA_SHA1.getJvmName());
        assertEquals("SHA256withECDSA", ECDSA_SHA256.getJvmName());
        assertEquals("SHA384withECDSA", ECDSA_SHA384.getJvmName());
        assertEquals("SHA512withECDSA", ECDSA_SHA512.getJvmName());
    }

    @Test
    public void getWithPortableName() throws Exception {
        for (final Algorithm algorithm : Algorithm.values()) {
            assertEquals(algorithm, Algorithm.get(algorithm.getPortableName()));
        }
    }

    @Test
    public void getWithJvmName() throws Exception {
        for (final Algorithm algorithm : Algorithm.values()) {
            assertEquals(algorithm, Algorithm.get(algorithm.getJvmName()));
        }
    }

    @Test
    public void getNotCaseSensitive() throws Exception {
        for (final Algorithm algorithm : Algorithm.values()) {
            assertEquals(algorithm, Algorithm.get(algorithm.getJvmName().toLowerCase()));
            assertEquals(algorithm, Algorithm.get(algorithm.getJvmName().toUpperCase()));

            assertEquals(algorithm, Algorithm.get(algorithm.getPortableName().toLowerCase()));
            assertEquals(algorithm, Algorithm.get(algorithm.getPortableName().toUpperCase()));
        }
    }

    @Test
    public void nonAlphaNumericsIgnored() throws Exception {
        for (final Algorithm algorithm : Algorithm.values()) {
            assertEquals(algorithm, Algorithm.get(algorithm.getPortableName().replace("-", " :-./ ")));
            assertEquals(algorithm, Algorithm.get(algorithm.getJvmName().replace("with", " -/with:.")));
        }
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void unsupportedAlgorithmException() throws Exception {
        Algorithm.get("HmacMD256");
    }
}