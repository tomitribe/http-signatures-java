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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public enum Signatures {
    ;

    private static final String REQUEST_TARGET = "(request-target)";

    public static String createSigningString(final List<String> required, String method, final String uri, final HeaderReader headers) {
        method = lowercase(method);

        final List<String> list = new ArrayList<String>(required.size());
        for (final String key : required) {
            if (REQUEST_TARGET.equals(key)) {
                list.add(Join.join(" ", "(request-target):", method, uri));

            } else {
                final String value = headers.read(key);
                if (value == null) throw new MissingRequiredHeaderException(key);

                list.add(key + ": " + value);
            }
        }

        return Join.join("\n", list);
    }

    private static String lowercase(final String spec) {
        return spec.toLowerCase(Locale.ENGLISH);
    }
}
