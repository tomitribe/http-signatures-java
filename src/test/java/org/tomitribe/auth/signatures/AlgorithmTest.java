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

import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA1;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA224;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA256;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA384;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA3_256;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA3_384;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA3_512;
import static org.tomitribe.auth.signatures.Algorithm.DSA_SHA512;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA1;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA256;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA256_P1363;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA384;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA384_P1363;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA3_256;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA3_384;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA3_512;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA512;
import static org.tomitribe.auth.signatures.Algorithm.ECDSA_SHA512_P1363;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA1;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA224;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA256;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA384;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA512;
import static org.tomitribe.auth.signatures.Algorithm.RSA_PSS;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA1;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA256;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA384;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA3_256;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA3_384;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA3_512;
import static org.tomitribe.auth.signatures.Algorithm.RSA_SHA512;

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
        assertEquals("rsa-sha3-256", RSA_SHA3_256.getPortableName());
        assertEquals("rsa-sha3-384", RSA_SHA3_384.getPortableName());
        assertEquals("rsa-sha3-512", RSA_SHA3_512.getPortableName());
        assertEquals("rsassa-pss", RSA_PSS.getPortableName());
        assertEquals("dsa-sha1", DSA_SHA1.getPortableName());
        assertEquals("dsa-sha224", DSA_SHA224.getPortableName());
        assertEquals("dsa-sha256", DSA_SHA256.getPortableName());
        assertEquals("dsa-sha384", DSA_SHA384.getPortableName());
        assertEquals("dsa-sha512", DSA_SHA512.getPortableName());
        assertEquals("dsa-sha3-256", DSA_SHA3_256.getPortableName());
        assertEquals("dsa-sha3-384", DSA_SHA3_384.getPortableName());
        assertEquals("dsa-sha3-512", DSA_SHA3_512.getPortableName());
        assertEquals("ecdsa-sha1", ECDSA_SHA1.getPortableName());
        assertEquals("ecdsa-sha256", ECDSA_SHA256.getPortableName());
        assertEquals("ecdsa-sha384", ECDSA_SHA384.getPortableName());
        assertEquals("ecdsa-sha512", ECDSA_SHA512.getPortableName());
        assertEquals("ecdsa-sha3-256", ECDSA_SHA3_256.getPortableName());
        assertEquals("ecdsa-sha3-384", ECDSA_SHA3_384.getPortableName());
        assertEquals("ecdsa-sha3-512", ECDSA_SHA3_512.getPortableName());
        assertEquals("ecdsa-sha256-p1363", ECDSA_SHA256_P1363.getPortableName());
        assertEquals("ecdsa-sha384-p1363", ECDSA_SHA384_P1363.getPortableName());
        assertEquals("ecdsa-sha512-p1363", ECDSA_SHA512_P1363.getPortableName());
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
        assertEquals("SHA3-256withRSA", RSA_SHA3_256.getJvmName());
        assertEquals("SHA3-384withRSA", RSA_SHA3_384.getJvmName());
        assertEquals("SHA3-512withRSA", RSA_SHA3_512.getJvmName());
        assertEquals("RSASSA-PSS", RSA_PSS.getJvmName());
        assertEquals("SHA1withDSA", DSA_SHA1.getJvmName());
        assertEquals("SHA224withDSA", DSA_SHA224.getJvmName());
        assertEquals("SHA256withDSA", DSA_SHA256.getJvmName());
        assertEquals("SHA384withDSA", DSA_SHA384.getJvmName());
        assertEquals("SHA512withDSA", DSA_SHA512.getJvmName());
        assertEquals("SHA1withECDSA", ECDSA_SHA1.getJvmName());
        assertEquals("SHA256withECDSA", ECDSA_SHA256.getJvmName());
        assertEquals("SHA384withECDSA", ECDSA_SHA384.getJvmName());
        assertEquals("SHA512withECDSA", ECDSA_SHA512.getJvmName());
        assertEquals("SHA3-256withECDSA", ECDSA_SHA3_256.getJvmName());
        assertEquals("SHA3-384withECDSA", ECDSA_SHA3_384.getJvmName());
        assertEquals("SHA3-512withECDSA", ECDSA_SHA3_512.getJvmName());
        assertEquals("SHA256withECDSAinP1363Format", ECDSA_SHA256_P1363.getJvmName());
        assertEquals("SHA384withECDSAinP1363Format", ECDSA_SHA384_P1363.getJvmName());
        assertEquals("SHA512withECDSAinP1363Format", ECDSA_SHA512_P1363.getJvmName());
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

    @Test
    public void getSigningAlgorithm() throws Exception {
        for (final SigningAlgorithm algorithm : SigningAlgorithm.values()) {
            final SigningAlgorithm s = SigningAlgorithm.get(algorithm.getAlgorithmName());
            assertEquals(algorithm, s);
        }
    }
}