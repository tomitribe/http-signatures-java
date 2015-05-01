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

import java.security.Provider;
import java.util.Objects;

public enum Algorithm {

    HMACSHA1("HmacSHA1", "hmac-sha1"),
    HMACSHA224("HmacSHA224", "hmac-sha224"),
    HMACSHA256("HmacSHA256", "hmac-sha256"),
    HMACSHA384("HmacSHA384", "hmac-sha384"),
    HMACSHA512("HmacSHA512", "hmac-sha512");

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
        try {
            return valueOf(normalize(name));
        } catch (IllegalArgumentException e) {
            throw new UnsupportedAlgorithmException(name);
        }
    }

    private static String normalize(String algorithm) {
        return algorithm.replaceAll("[ .:-]+", "").toUpperCase();
    }
}
