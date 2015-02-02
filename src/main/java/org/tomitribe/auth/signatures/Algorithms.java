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

import static org.tomitribe.auth.signatures.Strings.lc;
import static org.tomitribe.auth.signatures.Strings.ucfirst;
import static org.tomitribe.auth.signatures.Strings.uppercase;

public class Algorithms {

    public static String resolveAlgorithm(final String algorithm, final Provider provider) {
        Objects.requireNonNull(algorithm, "algorithm cannot be null");

        return null;
    }

    public static String toPortableName(final String algorithm) {

        { // space or dash delimiter
            final String[] split = algorithm.split("[- ]");
            if (split.length == 2) {
                final String keyType = ucfirst(lc(split[0]));
                final String hashType = uppercase(split[1]);

                return keyType + "-" + hashType;
            }
        }

        { // no delimiter
            final String[] split = algorithm.toLowerCase().split("sha");
            if (split.length == 2) {
                final String keyType = ucfirst(lc(split[0]));
                final String hashType = "SHA" + uppercase(split[1]);

                return keyType + "-" + hashType;
            }
        }

        throw new IllegalArgumentException("Unsupported algorithm format: " + algorithm);
    }

    public static String toJvmName(final String algorithm) {
        return "";
    }

//    public static Set<String> guesses(final String algorithm) {
//
//        final LinkedHashSet<String> guesses = new LinkedHashSet<String>();
//
//        {
//            final String[] split = algorithm.split("-");
//            if (split.length == 2) {
//                final String keyType = ucfirst(lc(split[0]));
//                final String hashType = uppercase(split[1]);
//
//                guesses.add(keyType + hashType);
//            }
//        }
//
//        if (guesses.size() == 0) {
//            final String[] split = algorithm.split("sha");
//            if (split.length == 2) {
//                final String keyType = ucfirst(lc(split[0]));
//                final String hashType = "SHA" + split[1];
//
//                guesses.add(keyType + hashType);
//            }
//        }
//
//        guesses.add(algorithm);
//
//        return guesses;
//    }
}
