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

import java.util.ArrayList;
import java.util.List;

public class AlgorithmTest extends Assert {

    private static final String[] hmac = {"Hmac", "HMAC", "hmac", "hMaC"};
    private static final String[] delimiters = {"", " ", "-"};
    private static final String[] sha = {"sha", "SHA", "sha", "SHA", "sHa"};

    @Test
    public void testToPortableName() throws Exception {

        assertPortableName("hmac-sha1", hmac, delimiters, sha, "1");
        assertPortableName("hmac-sha256", hmac, delimiters, sha, "256");
        assertPortableName("hmac-sha512", hmac, delimiters, sha, "512");
    }

    @Test
    public void testToJvmName() throws Exception {

        assertJvmName("HmacSHA1", hmac, delimiters, sha, "1");
        assertJvmName("HmacSHA256", hmac, delimiters, sha, "256");
        assertJvmName("HmacSHA512", hmac, delimiters, sha, "512");
    }

    private void assertPortableName(final String expected, final String[] type, final String[] delimiters, final String[] sha, final String bits) {
        for (String text : matrix(type, delimiters, sha, new String[]{bits})) {
            assertEquals(expected, Algorithm.toPortableName(text));
        }
    }

    private void assertJvmName(final String expected, final String[] type, final String[] delimiters, final String[] sha, final String bits) {
        for (String text : matrix(type, delimiters, sha, new String[]{bits})) {
            assertEquals(expected, Algorithm.toJvmName(text));
        }
    }

    private Iterable<String> matrix(String[] hmac, String[] delimiters, String[] sha, String[] one) {
        // this could be fancier and create the strings as we iterate,
        // but this is good enough
        final List<String> list = new ArrayList<String>();
        for (String h : hmac) {
            for (String d : delimiters) {
                for (String s : sha) {
                    for (String o : one) {
                        list.add(h + d + s + o);
                    }
                }
            }
        }
        return list;
    }
}