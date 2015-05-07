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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SignatureException;
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

    private final Key symmetricKey;
    private final PrivateKey asymmetricKey;
    private final Signature signature;
    private final Algorithm algorithm;
    private final Provider provider;

    public Signer(final Key key, final Signature signature) {
        this(key, signature, null);
    }

    public Signer(final Key key, final Signature signature, final Provider provider) {
        this.signature = requireNonNull(signature, "Signature cannot be null");
        this.algorithm = signature.getAlgorithm();
        this.provider = provider;

        if (java.security.Signature.class.equals(algorithm.getType())) {
            this.asymmetricKey = PrivateKey.class.cast(key);
            this.symmetricKey = null;
        } else if (Mac.class.equals(algorithm.getType())) {
            this.asymmetricKey = null;
            this.symmetricKey = key;
        } else {
            throw new UnsupportedAlgorithmException(String.format("Unknown Algorithm type %s %s", algorithm.getPortableName(), algorithm.getType().getName()));
        }

        // check that the JVM really knows the algorithm we are going to use
        try {
            sign("validation".getBytes());
        } catch (final Exception e) {
            throw new UnsupportedAlgorithmException("Can't initialise the Signer using the provided algorithm", e);
        }
    }

    public Signature sign(final String method, final String uri, final Map<String, String> headers) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final String signingString = createSigningString(method, uri, headers);
        final String signedAndEncodedString = sign(signingString);

        return new Signature(signature.getKeyId(), signature.getAlgorithm(), signedAndEncodedString, signature.getHeaders());
    }

    String sign(final String signingString) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        final byte[] signature = sign(signingString.getBytes("UTF-8"));
        final byte[] encoded = Base64.encodeBase64(signature);
        return new String(encoded, "UTF-8");
    }

    private byte[] sign(byte[] signingStringBytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        if (java.security.Signature.class.equals(algorithm.getType())) {
            final java.security.Signature instance = provider == null ? java.security.Signature.getInstance(algorithm.getJmvName()) : java.security.Signature.getInstance(algorithm.getJmvName(), provider);
            instance.initSign(asymmetricKey);
            instance.update(signingStringBytes);
            return instance.sign();
        }

        if (Mac.class.equals(algorithm.getType())) {
            return hash(signingStringBytes);
        }

        throw new IllegalStateException("Unknown Algorithm type " + algorithm.getType().getName());
    }

    String createSigningString(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return Signatures.createSigningString(signature.getHeaders(), method, uri, headers);
    }

    private byte[] hash(final byte[] bytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = provider == null ? Mac.getInstance(algorithm.getJmvName()) : Mac.getInstance(algorithm.getJmvName(), provider);
        mac.init(this.symmetricKey);
        return mac.doFinal(bytes);
    }
}
