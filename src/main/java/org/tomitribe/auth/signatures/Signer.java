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

import javax.crypto.Mac;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * It is an intentional part of the design that the same Signer instance
 * can be reused on several HTTP Messages in a multi-threaded fashion
 * <p/>
 * The supplied Signature instance will be used as the basis for all
 * future signatures created from this Signer.
 * <p/>
 * Each call to 'sign' will emit a Signature with the same 'keyId',
 * 'algorithm', 'headers' but a newly calculated 'signature'
 */
public class Signer {

    private final Key key;
    private final Signature signature;
    private final Algorithm algorithm;
    private final Provider provider;

    public Signer(final Key key, final Signature signature) {
        this(key, signature, null);
    }

    public Signer(final Key key, final Signature signature, final Provider provider) {
        this.key = requireNonNull(key, "Key cannot be null");
        this.signature = requireNonNull(signature, "Signature cannot be null");
        this.algorithm = Algorithm.get(signature.getAlgorithm());
        this.provider = provider;

        // check that the JVM really knows the algorithm we are going to use
        try {
            hash("validation".getBytes());

        } catch (final Exception e) {
            throw new UnsupportedAlgorithmException("Can't initialise the Signer using the provided algorithm", e);
        }
    }

    public Signature sign(final String method, final String uri, final Map<String, String> headers) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        final String signingString = createSigningString(method, uri, headers);
        final String signedAndEncodedString = sign(signingString);

        return new Signature(signature.getKeyId(), signature.getAlgorithm(), signedAndEncodedString, signature.getHeaders());
    }

    String sign(final String signingString) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        final byte[] hashed = hash(signingString.getBytes("UTF-8"));
        final byte[] encoded = Base64.encodeBase64(hashed);

        return new String(encoded, "UTF-8");
    }

    String createSigningString(String method, final String uri, Map<String, String> headers) throws IOException {
        method = lowercase(method);
        headers = lowercase(headers);

        final List<String> list = new ArrayList<String>(signature.getHeaders().size());

        for (final String key : signature.getHeaders()) {
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


    private byte[] hash(final byte[] bytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = provider == null ? Mac.getInstance(algorithm.getJmvName()) : Mac.getInstance(algorithm.getJmvName(), provider);
        mac.init(this.key);
        return mac.doFinal(bytes);
    }


}
