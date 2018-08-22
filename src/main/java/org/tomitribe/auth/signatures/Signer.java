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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * It is an intentional part of the design that the same Signer instance
 * can be reused on several HTTP Messages in a multi-threaded fashion
 *
 * <p>
 * The supplied Signature instance will be used as the basis for all
 * future signatures created from this Signer.
 *
 * <p>
 *  Each call to 'sign' will emit a Signature with the same 'keyId',
 * 'algorithm', 'headers' but a newly calculated 'signature'
 *
 */
public class Signer {

    private final Sign sign;
    private final Signature signature;
    private final Algorithm algorithm;
    private final Provider provider;

    public Signer(final Key key, final Signature signature) {
        this(key, signature, null);
    }

    public Signer(final Key key, final Signature signature, final Provider provider) {
        requireNonNull(key, "Key cannot be null");
        this.signature = requireNonNull(signature, "Signature cannot be null");
        this.algorithm = signature.getAlgorithm();
        this.provider = provider;

        if (java.security.Signature.class.equals(algorithm.getType())) {

            this.sign = new Asymmetric(PrivateKey.class.cast(key));

        } else if (Mac.class.equals(algorithm.getType())) {

            this.sign = new Symmetric(key);

        } else {

            throw new UnsupportedAlgorithmException(String.format("Unknown Algorithm type %s %s", algorithm.getPortableName(), algorithm.getType().getName()));
        }

        // check that the JVM really knows the algorithm we are going to use
        try {

            sign.sign("validation".getBytes());

        } catch (final RuntimeException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalStateException("Can't initialise the Signer using the provided algorithm and key", e);
        }
    }

    @Deprecated // use sign(String, String, HeaderReader headers)
    public Signature sign(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return sign(method, uri, new HeaderReader.Map(headers));
    }

    public Signature sign(final String method, final String uri, final HeaderReader headers) throws IOException {

        final String signingString = createSigningString(method, uri, headers);

        final byte[] binarySignature = sign.sign(signingString.getBytes("UTF-8"));

        final byte[] encoded = Base64.encodeBase64(binarySignature);

        final String signedAndEncodedString = new String(encoded, "UTF-8");

        return new Signature(signature.getKeyId(), signature.getAlgorithm(), signedAndEncodedString, signature.getHeaders());
    }

    @Deprecated // use createSigningString(String, String, HeaderReader)
    public String createSigningString(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return createSigningString(method, uri, new HeaderReader.Map(headers));
    }

    public String createSigningString(final String method, final String uri, final HeaderReader headers) throws IOException {
        return Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
    }

    private interface Sign {
        byte[] sign(byte[] signingStringBytes);
    }

    private class Asymmetric implements Sign {

        private final PrivateKey key;

        private Asymmetric(final PrivateKey key) {
            this.key = key;
        }

        @Override
        public byte[] sign(final byte[] signingStringBytes) {
            try {

                final java.security.Signature instance = provider == null ?
                        java.security.Signature.getInstance(algorithm.getJmvName()) :
                        java.security.Signature.getInstance(algorithm.getJmvName(), provider);

                instance.initSign(key);
                instance.update(signingStringBytes);
                return instance.sign();

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);
            }
        }
    }

    private class Symmetric implements Sign {

        private final Key key;

        private Symmetric(final Key key) {
            this.key = key;
        }

        @Override
        public byte[] sign(final byte[] signingStringBytes) {

            try {

                final Mac mac = provider == null ? Mac.getInstance(algorithm.getJmvName()) : Mac.getInstance(algorithm.getJmvName(), provider);
                mac.init(key);
                return mac.doFinal(signingStringBytes);

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);

            }
        }
    }
}
