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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Signatures {

    public static String createSigningString(final List<String> required, String method, final String uri, Map<String, String> headers) throws IOException {
        method = lowercase(method);
        headers = lowercase(headers);

        final List<String> list = new ArrayList<String>(required.size());

        for (final String key : required) {
            if ("(request-target)".equals(key)) {
                list.add(Join.join(" ", "(request-target):", method, uri));

            } else {
                final String value = headers.get(key);
                if (value == null) throw new MissingRequiredHeaderException(key);

                list.add(key + ": " + value);
            }
        }

        return Join.join("\n", list);
    }

    private static Map<String, String> lowercase(final Map<String, String> headers) {
        final Map<String, String> map = new HashMap<String, String>();
        for (final Map.Entry<String, String> entry : headers.entrySet()) {
            map.put(entry.getKey().toLowerCase(), entry.getValue());
        }

        return map;
    }

    private static String lowercase(final String spec) {
        return spec.toLowerCase();
    }
}
