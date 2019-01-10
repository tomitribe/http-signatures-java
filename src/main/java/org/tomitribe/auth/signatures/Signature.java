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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Signature {

    /**
     * REQUIRED.  The `keyId` field is an opaque string that the server can
     * use to look up the component they need to validate the signature.  It
     * could be an SSH key fingerprint, a URL to machine-readable key data,
     * an LDAP DN, etc.  Management of keys and assignment of `keyId` is out
     * of scope for this document.
     */
    private final String keyId;

    /**
     * REQUIRED.  The `algorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms and MUST NOT be marked "deprecated".
     */
    private final Algorithm algorithm;

    /**
     * OPTIONAL.  The `headers` parameter is used to specify the list of
     * HTTP headers included when generating the signature for the message.
     * If specified, it should be a lowercased, quoted list of HTTP header
     * fields, separated by a single space character.  If not specified,
     * implementations MUST operate as if the field were specified with a
     * single value, the `Date` header, in the list of HTTP headers.  Note
     * that the list order is important, and MUST be specified in the order
     * the HTTP header field-value pairs are concatenated together during
     * signing.
     */
    private final String signature;

    /**
     * REQUIRED.  The `signature` parameter is a base 64 encoded digital
     * signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
     * client uses the `algorithm` and `headers` signature parameters to
     * form a canonicalized `signing string`.  This `signing string` is then
     * signed with the key associated with `keyId` and the algorithm
     * corresponding to `algorithm`.  The `signature` parameter is then set
     * to the base 64 encoding of the signature.
     */
    private final List<String> headers;

    public Signature(final String keyId, final String algorithm, final String signature, final String... headers) {
        this(keyId, getAlgorithm(algorithm), signature, headers);
    }

    private static Algorithm getAlgorithm(String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("Algorithm cannot be null");
        return Algorithm.get(algorithm);
    }

    public Signature(final String keyId, final Algorithm algorithm, final String signature, final String... headers) {
        this(keyId, algorithm, signature, Arrays.asList(headers));
    }

    public Signature(final String keyId, final String algorithm, final String signature, final List<String> headers) {
        this(keyId, getAlgorithm(algorithm), signature, headers);
    }

    public Signature(final String keyId, Algorithm algorithm, final String signature, final List<String> headers) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId is required.");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm is required.");
        }

        this.keyId = keyId;
        this.algorithm = algorithm;

        // this is the only one that can be null cause the object
        // can be used as a template/specification
        this.signature = signature;

        if (headers.size() == 0) {
            final List<String> list = Arrays.asList("date");
            this.headers = Collections.unmodifiableList(list);
        } else {
            this.headers = Collections.unmodifiableList(lowercase(headers));
        }
    }

    private List<String> lowercase(List<String> headers) {
        final List<String> list = new ArrayList<String>(headers.size());
        for (String header : headers) {
            list.add(header.toLowerCase());
        }
        return list;
    }

    public String getKeyId() {
        return keyId;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public String getSignature() {
        return signature;
    }

    public List<String> getHeaders() {
        return headers;
    }

    public static Signature fromString(String authorization) {
        try {
            authorization = normalize(authorization);

            final Map<String, String> map = new HashMap<String, String>();

            final Pattern rfc2617Param = Pattern.compile("(\\w+)=\"([^\"]*)\"");
            final Matcher matcher = rfc2617Param.matcher(authorization);
            while (matcher.find()) {
                final String key = matcher.group(1).toLowerCase();
                final String value = matcher.group(2);
                map.put(key, value);
            }

            final List<String> headers = new ArrayList<String>();
            final String headerString = map.get("headers");
            if (headerString != null) {
                Collections.addAll(headers, headerString.toLowerCase().split(" +"));
            }

            final String keyid = map.get("keyid");
            if (keyid == null) throw new MissingKeyIdException();

            final String algorithm = map.get("algorithm");
            if (algorithm == null) throw new MissingAlgorithmException();

            final String signature = map.get("signature");
            if (signature == null) throw new MissingSignatureException();

            final Algorithm parsedAlgorithm = Algorithm.get(algorithm);

            return new Signature(keyid, parsedAlgorithm, signature, headers);

        } catch (AuthenticationException e) {
            throw e;
        } catch (Throwable e) {
            throw new UnparsableSignatureException(authorization, e);
        }
    }

    private static String normalize(String authorization) {
        final String start = "signature ";

        final String prefix = authorization.substring(0, start.length()).toLowerCase();

        if (prefix.equals(start)) {
            authorization = authorization.substring(start.length());
        }
        return authorization.trim();
    }

    @Override
    public String toString() {
        return "Signature " +
                "keyId=\"" + keyId + '\"' +
                ",algorithm=\"" + algorithm + '\"' +
                ",headers=\"" + Join.join(" ", headers) + '\"' +
                ",signature=\"" + signature + '\"';
    }
}
