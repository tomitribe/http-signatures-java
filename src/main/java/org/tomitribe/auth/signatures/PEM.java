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


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

/**
 * A PEM utility that can be used to read keys from PEM. With this PEM utility,
 * private keys in either PKCS#1 or PKCS#8 PEM encoded format can be read
 * without the need to depend on the Bouncy Castle library.
 * <p>
 * Some background information:
 * <ul>
 * <li>Interestingly, the creation of a CloudFront Key Pair via the AWS console
 * would result in a private key in PKCS#1 PEM format.</li>
 * <li>Unfortunately, the JDK doesn't provide a means to load PEM key encoded in
 * PKCS#1 without adding the Bouncy Castle to the classpath. The JDK can only
 * load PEM key encoded in PKCS#8 encoding.</li>
 * <li>One the other hand, one can use openssl to convert a PEM file from PKCS#1
 * to PKCS#8. Example:
 *
 * <pre>
 * openssl pkcs8 -topk8 -in pk-APKAJM22QV32R3I2XVIQ.pem -inform pem -out pk-APKAJM22QV32R3I2XVIQ_pk8.pem  -outform pem -nocrypt
 * </pre>
 *
 * </li>
 * </ul>
 */
public enum PEM {
    ;
    private static final String BEGIN_MARKER = "-----BEGIN ";

    /**
     * Returns the first private key that is found from the input stream of a
     * PEM file.
     *
     * @throws java.security.spec.InvalidKeySpecException
     *             if failed to convert the DER bytes into a private key.
     * @throws IllegalArgumentException
     *             if no private key is found.
     */
    public static PrivateKey readPrivateKey(final InputStream is) throws InvalidKeySpecException, IOException {

        final List<PEMObject> objects = readPEMObjects(is);
        for (final PEMObject object : objects) {
            switch (object.getPEMObjectType()) {
                case PRIVATE_KEY_PKCS1:
                    return RSA.privateKeyFromPKCS1(object.getDerBytes());
                case PRIVATE_KEY_PKCS8:
                    return RSA.privateKeyFromPKCS8(object.getDerBytes());
                default:
                    break;
            }
        }
        throw new IllegalArgumentException("Found no private key");
    }

    /**
     * Returns the first public key that is found from the input stream of a PEM
     * file.
     *
     * @throws java.security.spec.InvalidKeySpecException
     *             if failed to convert the DER bytes into a public key.
     * @throws IllegalArgumentException
     *             if no public key is found.
     */
    public static PublicKey readPublicKey(final InputStream is) throws InvalidKeySpecException, IOException {

        for (final PEMObject object : readPEMObjects(is)) {

            switch (object.getPEMObjectType()) {

                case PUBLIC_KEY_X509:

                    return RSA.publicKeyFrom(object.getDerBytes());

                default:
                    break;
            }
        }
        throw new IllegalArgumentException("Found no public key");
    }

    /**
     * A lower level API used to returns all PEM objects that can be read off
     * from the input stream of a PEM file.
     * <p>
     * This method can be useful if more than one PEM object of different types
     * are embedded in the same PEM file.
     */
    private static List<PEMObject> readPEMObjects(final InputStream is) throws IOException {

        final BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        try {
            final List<PEMObject> pemContents = new ArrayList<PEMObject>();
        /*
         * State of reading: set to true if reading content between a
         * begin-marker and end-marker; false otherwise.
         */
            boolean readingContent = false;
            String beginMarker = null;
            String endMarker = null;
            StringBuffer sb = null;
            String line;

            while ((line = reader.readLine()) != null) {
                if (readingContent) {
                    if (line.contains(endMarker)) {
                        pemContents.add( // completed reading one PEM object
                                new PEMObject(beginMarker, org.tomitribe.auth.signatures.Base64.decodeBase64(sb.toString().getBytes("UTF-8"))));
                        readingContent = false;
                    } else {
                        sb.append(line.trim());
                    }
                } else {
                    if (line.contains(BEGIN_MARKER)) {
                        readingContent = true;
                        beginMarker = line.trim();
                        endMarker = beginMarker.replace("BEGIN", "END");
                        sb = new StringBuffer();
                    }
                }
            }
            return pemContents;
        } finally {
            try {
                reader.close();
            } catch (IOException ignore) {
            }
        }
    }

    /**
     * A PEM object in a PEM file.
     *<p>
     * A PEM file can contain one or multiple PEM objects, each with a beginning
     * and ending marker.
     */
    static class PEMObject {
        private final String beginMarker;
        private final byte[] derBytes;

        public PEMObject(final String beginMarker, final byte[] derBytes) {
            this.beginMarker = beginMarker;
            this.derBytes = derBytes.clone();
        }

        public String getBeginMarker() {
            return beginMarker;
        }

        public byte[] getDerBytes() {
            return derBytes.clone();
        }

        public PEMObjectType getPEMObjectType() {
            return PEMObjectType.fromBeginMarker(beginMarker);
        }
    }

    /**
     * The type of a specific PEM object in a PEM file.
     *<p>
     * A PEM file can contain one or multiple PEM objects, each with a beginning
     * and ending marker.
     */
    static enum PEMObjectType {
        PRIVATE_KEY_PKCS1("-----BEGIN RSA PRIVATE KEY-----"),
        PRIVATE_KEY_PKCS8("-----BEGIN PRIVATE KEY-----"),
        PUBLIC_KEY_X509("-----BEGIN PUBLIC KEY-----"),
        CERTIFICATE_X509("-----BEGIN CERTIFICATE-----");
        private final String beginMarker;

        public String getBeginMarker() {
            return beginMarker;
        }

        PEMObjectType(final String beginMarker) {
            this.beginMarker = beginMarker;
        }

        public static PEMObjectType fromBeginMarker(final String beginMarker) {
            for (PEMObjectType e : PEMObjectType.values()) {
                if (e.getBeginMarker().equals(beginMarker))
                    return e;
            }
            return null;
        }
    }
}
