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
import java.security.*;
import java.util.Arrays;
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
 *  Each call to 'verify' will emit a Signature with the same 'keyId',
 * 'algorithm', 'headers' but a newly calculated 'signature'
 *
 */
public class Verifier {

    private final Verify verify;
    private final Signature signature;
    private final Algorithm algorithm;
    private final Provider provider;

    public Verifier(final Key key, final Signature signature) {
        this(key, signature, null);
    }

    public Verifier(final Key key, final Signature signature, final Provider provider) {
        requireNonNull(key, "Key cannot be null");
        this.signature = requireNonNull(signature, "Signature cannot be null");
        this.algorithm = signature.getAlgorithm();
        this.provider = provider;

        if (java.security.Signature.class.equals(algorithm.getType())) {

            this.verify = new Asymmetric(PublicKey.class.cast(key));

        } else if (Mac.class.equals(algorithm.getType())) {

            this.verify = new Symmetric(key);

        } else {

            throw new UnsupportedAlgorithmException(String.format("Unknown Algorithm type %s %s", algorithm.getPortableName(), algorithm.getType().getName()));
        }

        // check that the JVM really knows the algorithm we are going to use
        try {

            verify.verify("validation".getBytes());

        } catch (final RuntimeException e) {

            throw (RuntimeException) e;

        } catch (final Exception e) {

            throw new IllegalStateException("Can't initialise the Signer using the provided algorithm and key", e);
        }
    }

    public boolean verify(final String method, final String uri, final Map<String, String> headers) throws IOException, NoSuchAlgorithmException, SignatureException {

        final String signingString = createSigningString(method, uri, headers);

        return verify.verify(signingString.getBytes());
    }

    public String createSigningString(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
    }

    private interface Verify {
        boolean verify(byte[] signingStringBytes);
    }

    private class Asymmetric implements Verify {

        private final PublicKey key;

        private Asymmetric(final PublicKey key) {
            this.key = key;
        }

        @Override
        public boolean verify(final byte[] signingStringBytes) {
            try {

                final java.security.Signature instance = provider == null ?
                        java.security.Signature.getInstance(algorithm.getJmvName()) :
                        java.security.Signature.getInstance(algorithm.getJmvName(), provider);

                instance.initVerify(key);
                instance.update(signingStringBytes);
                return instance.verify(Base64.decodeBase64(signature.getSignature().getBytes()));

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);
            }
        }
    }

    private class Symmetric implements Verify {

        private final Key key;

        private Symmetric(final Key key) {
            this.key = key;
        }

        @Override
        public boolean verify(final byte[] signingStringBytes) {

            try {

                final Mac mac = provider == null ? Mac.getInstance(algorithm.getJmvName()) : Mac.getInstance(algorithm.getJmvName(), provider);
                mac.init(key);
                byte[] hash = mac.doFinal(signingStringBytes);
                return Arrays.equals(hash, signature.getSignature().getBytes());

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);

            }
        }
    }
}
