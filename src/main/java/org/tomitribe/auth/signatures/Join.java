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

import java.util.Collection;

public class Join {

    private Join() {
        // no-op
    }

    public static String join(final String delimiter, final Collection collection) {
        if (collection.size() == 0) return "";

        final StringBuilder sb = new StringBuilder();

        for (final Object obj : collection) {
            sb.append(obj).append(delimiter);
        }

        return sb.substring(0, sb.length() - delimiter.length());
    }

    public static String join(final String delimiter, final Object... collection) {
        if (collection.length == 0) return "";

        final StringBuilder sb = new StringBuilder();

        for (final Object obj : collection) {
            sb.append(obj).append(delimiter);
        }

        return sb.substring(0, sb.length() - delimiter.length());
    }
}
