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

import java.util.HashMap;
import java.util.Map;

public enum Algorithm {

    // hmac
    HMAC_SHA1("HmacSHA1", "hmac-sha1"),
    HMAC_SHA224("HmacSHA224", "hmac-sha224"),
    HMAC_SHA256("HmacSHA256", "hmac-sha256"),
    HMAC_SHA384("HmacSHA384", "hmac-sha384"),
    HMAC_SHA512("HmacSHA512", "hmac-sha512"),

    // rsa
    RSA_SHA1("SHA1withRSA", "rsa-sha1"),
    RSA_SHA256("SHA256withRSA", "rsa-sha256"),
    RSA_SHA384("SHA384withRSA", "rsa-sha384"),
    RSA_SHA512("SHA512withRSA", "rsa-sha512"),

    // dsa
    DSA_SHA1("SHA1withDSA", "dsa-sha1"),
    DSA_SHA224("SHA224withDSA", "dsa-sha224"),
    DSA_SHA256("SHA256withDSA", "dsa-sha256"),;

    private static final Map<String, Algorithm> aliases = new HashMap<String, Algorithm>();

    static {
        for (final Algorithm algorithm : Algorithm.values()) {
            aliases.put(normalize(algorithm.getJmvName()), algorithm);
            aliases.put(normalize(algorithm.getPortableName()), algorithm);
        }
    }

    private final String portableName;
    private final String jmvName;

    Algorithm(final String jmvName, final String portableName) {
        this.portableName = portableName;
        this.jmvName = jmvName;
    }

    public String getPortableName() {
        return portableName;
    }

    public String getJmvName() {
        return jmvName;
    }

    public static String toPortableName(final String name) {
        return get(name).getPortableName();
    }

    public static String toJvmName(final String name) {
        return get(name).getJmvName();
    }

    public static Algorithm get(String name) {
        final Algorithm algorithm = aliases.get(normalize(name));

        if (algorithm != null) return algorithm;

        throw new UnsupportedAlgorithmException(name);
    }

    private static String normalize(String algorithm) {
        return algorithm.replaceAll("[^A-Za-z0-9]+", "").toLowerCase();
    }
}
