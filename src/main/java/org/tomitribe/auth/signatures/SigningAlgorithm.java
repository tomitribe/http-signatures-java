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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The algorithm parameter contains the name of the signature's Algorithm,
 * as registered in the HTTP Signature Algorithms Registry defined by this document.
 *
 * The signature verification is based on the signature's algorithm from the keyId
 * parameter rather than from this algorithm.
 * If algorithm is provided and differs from or is incompatible with the algorithm
 * or key material identified by keyId (for example, algorithm has a value of
 * rsa-sha256 but keyId identifies an EdDSA key), then a verification exception is
 * raised.
 *
 * The default value for this parameter should be "hs2019".
 *
 * @see <a href="https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html">https://www.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html</a>
 */
public enum SigningAlgorithm {

    /**
     * The actual cryptographic algorithm is derived from metadata associated
     * with keyId.
     *
     * Recommend support for:
     *   RSASSA-PSS [RFC8017] using SHA-512 [RFC6234]
     *   HMAC [RFC2104] using SHA-512 [RFC6234]
     *   ECDSA using curve P-256 [DSS] and SHA-512 [RFC6234]
     *   Ed25519ph, Ed25519ctx, and Ed25519 [RFC8032]
     */
    HS2019("hs2019", null),

    // Deprecated, SHA-1 is not secure.
    // Use hs2019.
    RSA_SHA1("rsa-sha1", new HashSet<Algorithm>(Arrays.asList(Algorithm.RSA_SHA1))),
    // Deprecated, specifying signature algorithm enables attack vector.
    // Use hs2019.
    RSA_SHA256("rsa-sha256", new HashSet<Algorithm>(Arrays.asList(Algorithm.RSA_SHA256))),
    // Deprecated, specifying signature algorithm enables attack vector.
    // Use hs2019.
    ECDSA_SHA256("ecdsa-sha256", new HashSet<Algorithm>(Arrays.asList(Algorithm.ECDSA_SHA256))),
    // Deprecated, specifying signature algorithm enables attack vector.
    // Use hs2019.
    HMAC_SHA256("hmac-sha256", new HashSet<Algorithm>(Arrays.asList(Algorithm.HMAC_SHA256))),
    ;

    private static final Map<String, SigningAlgorithm> aliases = new HashMap<String, SigningAlgorithm>();

    static {
        for (final SigningAlgorithm algorithmName : SigningAlgorithm.values()) {
            aliases.put(algorithmName.getAlgorithmName(), algorithmName);
        }
    }

    /**
     * An identifier for the HTTP Signature Algorithm.
     * The name MUST be an ASCII string consisting only of lower-case characters ("a" - "z"),
     * digits ("0" - "9"), and hyphens ("-"), and SHOULD NOT exceed 20 characters in length.
     * The identifier MUST be unique within the context of the registry.
     */
    private final String algorithmName;
    private final Set<Algorithm> supportedAlgorithms;

    SigningAlgorithm(final String algorithmName, final Set<Algorithm> supportedAlgorithms) {
        this.algorithmName = algorithmName;
        if (supportedAlgorithms != null) {
            this.supportedAlgorithms = Collections.unmodifiableSet(supportedAlgorithms);
        } else {
            this.supportedAlgorithms = null;
        }
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public Set<Algorithm> getSupportedAlgorithms() {
        return this.supportedAlgorithms;
    }

    /**
     * Returns the SigningAlgorithm with the specified name.
     *
     * @param name the name of the signing algorithm.
     * @return the SigningAlgorithm
     */
    public static SigningAlgorithm get(final String name) {
        final SigningAlgorithm algorithmName = aliases.get(name);
        if (algorithmName != null) return algorithmName;
        throw new UnsupportedAlgorithmException(name);
    }

    @Override
    public String toString() {
        return getAlgorithmName();
    }
}