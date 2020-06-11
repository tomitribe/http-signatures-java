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

            throw (RuntimeException) e;

        } catch (final Exception e) {

            throw new IllegalStateException("Can't initialise the Signer using the provided algorithm and key", e);
        }
    }

    public Signature sign(final String method, final String uri, final Map<String, String> headers) throws IOException {
        final Long created = System.currentTimeMillis();
        Long expires = signature.getSignatureMaxValidityMilliseconds();
        if (expires != null) {
            expires += created;
        }
        final String signingString = createSigningString(method, uri, headers, created, expires);

        final byte[] binarySignature = sign.sign(signingString.getBytes("UTF-8"));

        final byte[] encoded = Base64.encodeBase64(binarySignature);

        final String signedAndEncodedString = new String(encoded, "UTF-8");

        return new Signature(signature.getKeyId(), signature.getSigningAlgorithm(),
                             signature.getAlgorithm(), signature.getParameterSpec(),
                             signedAndEncodedString, signature.getHeaders(), null, created, expires);
    }

    /**
     * Create and return the string which is used as input for the cryptographic signature.
     * 
     * @param method The HTTP method.
     * @param uri The URI path and query parameters.
     * @param headers The HTTP headers.
     * @param created The time when the signature is created.
     * @param expires The time when the signature expires.
     * @return The signing string.
     * @throws IOException when an exception occurs while creating the signing string.
     */
    public String createSigningString(final String method, final String uri, final Map<String, String> headers,
            Long created, Long expires) throws IOException {
        return Signatures.createSigningString(signature.getHeaders(), method, uri, headers, created, expires);
    }

    /**
     * Create and return the string which is used as input for the cryptographic signature.
     * 
     * @param method The HTTP method.
     * @param uri The URI path and query parameters.
     * @param headers The HTTP headers.
     * @return The signing string.
     * @throws IOException when an exception occurs while creating the signing string.
     */
    public String createSigningString(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return Signatures.createSigningString(signature.getHeaders(), method, uri, headers,
            signature.getSignatureCreationTimeMilliseconds(), signature.getSignatureExpirationTimeMilliseconds());
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
                        java.security.Signature.getInstance(algorithm.getJvmName()) :
                        java.security.Signature.getInstance(algorithm.getJvmName(), provider);
                if (signature.getParameterSpec() != null) {
                    instance.setParameter(signature.getParameterSpec());
                }
                instance.initSign(key);
                instance.update(signingStringBytes);
                return instance.sign();

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJvmName());

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

                final Mac mac = provider == null ? Mac.getInstance(algorithm.getJvmName()) : Mac.getInstance(algorithm.getJvmName(), provider);
                mac.init(key);
                return mac.doFinal(signingStringBytes);

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJvmName());

            } catch (Exception e) {

                throw new IllegalStateException(e);

            }
        }
    }
}
