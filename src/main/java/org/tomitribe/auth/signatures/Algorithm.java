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

import javax.crypto.Mac;
import java.util.HashMap;
import java.util.Map;

/**
 * The cryptographic algorithms for the HTTP signature.
 */
public enum Algorithm {

    // hmac
    HMAC_SHA1("HmacSHA1", "hmac-sha1", Mac.class),
    HMAC_SHA224("HmacSHA224", "hmac-sha224", Mac.class),
    HMAC_SHA256("HmacSHA256", "hmac-sha256", Mac.class),
    HMAC_SHA384("HmacSHA384", "hmac-sha384", Mac.class),
    HMAC_SHA512("HmacSHA512", "hmac-sha512", Mac.class),

    // RSA PKCS#1 v1.5 signature
    RSA_SHA1("SHA1withRSA", "rsa-sha1", java.security.Signature.class),
    RSA_SHA256("SHA256withRSA", "rsa-sha256", java.security.Signature.class),
    RSA_SHA384("SHA384withRSA", "rsa-sha384", java.security.Signature.class),
    RSA_SHA512("SHA512withRSA", "rsa-sha512", java.security.Signature.class),

    RSA_SHA3_256("SHA3-256withRSA", "rsa-sha3-256", java.security.Signature.class),
    RSA_SHA3_384("SHA3-384withRSA", "rsa-sha3-384", java.security.Signature.class),
    RSA_SHA3_512("SHA3-512withRSA", "rsa-sha3-512", java.security.Signature.class),

    // RSA PSS signature
    // This algorithm requires parameter. For example:
    // new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
    RSA_PSS("RSASSA-PSS", "rsassa-pss", java.security.Signature.class),

    // dsa
    DSA_SHA1("SHA1withDSA", "dsa-sha1", java.security.Signature.class),
    DSA_SHA224("SHA224withDSA", "dsa-sha224", java.security.Signature.class),
    DSA_SHA256("SHA256withDSA", "dsa-sha256", java.security.Signature.class),
    DSA_SHA384("SHA384withDSA", "dsa-sha384", java.security.Signature.class),
    DSA_SHA512("SHA512withDSA", "dsa-sha512", java.security.Signature.class),

    // dsa with SHA3
    DSA_SHA3_256("SHA3-256withDSA", "dsa-sha3-256", java.security.Signature.class),
    DSA_SHA3_384("SHA3-384withDSA", "dsa-sha3-384", java.security.Signature.class),
    DSA_SHA3_512("SHA3-512withDSA", "dsa-sha3-512", java.security.Signature.class),

    // ecdsa
    // The format of the Signature bytes for these algorithms is an ASN.1 encoded
    // sequence as specified in RFC 3279 section 2.2.2.
    ECDSA_SHA1("SHA1withECDSA", "ecdsa-sha1", java.security.Signature.class),
    ECDSA_SHA256("SHA256withECDSA", "ecdsa-sha256", java.security.Signature.class),
    ECDSA_SHA384("SHA384withECDSA", "ecdsa-sha384", java.security.Signature.class),
    ECDSA_SHA512("SHA512withECDSA", "ecdsa-sha512", java.security.Signature.class),

    // ecdsa with SHA3
    ECDSA_SHA3_256("SHA3-256withECDSA", "ecdsa-sha3-256", java.security.Signature.class),
    ECDSA_SHA3_384("SHA3-384withECDSA", "ecdsa-sha3-384", java.security.Signature.class),
    ECDSA_SHA3_512("SHA3-512withECDSA", "ecdsa-sha3-512", java.security.Signature.class),

    // ecdsa in P1363 Format.
    // The ECDSA signature algorithms as defined in ANSI X9.62 with an output as
    // defined in IEEE P1363 format.
    // The signature is the raw concatenation of r and s.
    ECDSA_SHA256_P1363("SHA256withECDSAinP1363Format", "ecdsa-sha256-p1363", java.security.Signature.class),
    ECDSA_SHA384_P1363("SHA384withECDSAinP1363Format", "ecdsa-sha384-p1363", java.security.Signature.class),
    ECDSA_SHA512_P1363("SHA512withECDSAinP1363Format", "ecdsa-sha512-p1363", java.security.Signature.class),
    ;

    private static final Map<String, Algorithm> aliases = new HashMap<String, Algorithm>();

    static {
        for (final Algorithm algorithm : Algorithm.values()) {
            aliases.put(normalize(algorithm.getJvmName()), algorithm);
            aliases.put(normalize(algorithm.getPortableName()), algorithm);
        }
    }

    private final String portableName;
    // The algorithm name passed to java.security.Signature or Mac.class.
    private final String jvmName;
    private final Class type;

    Algorithm(final String jvmName, final String portableName, final Class type) {
        this.portableName = portableName;
        this.jvmName = jvmName;
        this.type = type;
    }

    public String getPortableName() {
        return portableName;
    }

    public String getJvmName() {
        return jvmName;
    }

    public Class getType() {
        return type;
    }

    public static String toPortableName(final String name) {
        return get(name).getPortableName();
    }

    public static String toJvmName(final String name) {
        return get(name).getJvmName();
    }

    public static Algorithm get(final String name) {
        final Algorithm algorithm = aliases.get(normalize(name));

        if (algorithm != null) return algorithm;

        throw new UnsupportedAlgorithmException(name);
    }

    private static String normalize(final String algorithm) {
        return algorithm.replaceAll("[^A-Za-z0-9]+", "").toLowerCase();
    }


    @Override
    public String toString() {
        return getPortableName();
    }
}
