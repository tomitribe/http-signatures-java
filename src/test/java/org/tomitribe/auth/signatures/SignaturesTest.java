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
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.tomitribe.auth.signatures;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class SignaturesTest {

    @Test
    public void createSigningString() {
        final List<String> required = Arrays.asList("date");

        final Map<String, String> headers = new HashMap<>();
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

        final String actual = Signatures.createSigningString(required, "GET", "/foo/Bar", headers, 1601396378077L, null);
        assertEquals("date: Tue, 07 Jun 2014 20:51:35 GMT", actual);
    }

    @Test
    public void testCreateSigningString() {
        final List<String> required = Arrays.asList("date");

        final Map<String, String> headers = new HashMap<>();
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

        final String actual = Signatures.createSigningString(required, "GET", "/foo/Bar", headers);
        assertEquals("date: Tue, 07 Jun 2014 20:51:35 GMT", actual);
    }
}
