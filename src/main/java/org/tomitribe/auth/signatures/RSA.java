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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility for RSA keys.
 */
public enum RSA {
    ;

    private static final String RSA = "RSA";

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    public static PrivateKey privateKeyFromPKCS8(final byte[] pkcs8) throws InvalidKeySpecException {
        try {
            final EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pkcs8);
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#1 format.
     */
    public static PrivateKey privateKeyFromPKCS1(final byte[] pkcs1) throws InvalidKeySpecException {
        try {
            final RSAPrivateCrtKeySpec privateKeySpec = newRSAPrivateCrtKeySpec(pkcs1);
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a public key constructed from the given DER bytes.
     */
    public static PublicKey publicKeyFrom(final byte[] derBytes) throws InvalidKeySpecException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            final EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(derBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // Extracted from:
    // http://oauth.googlecode.com/svn/code/branches/jmeter/jmeter/src/main/java/org/apache/jmeter/protocol/oauth/sampler/PrivateKeyReader.java
    // See p.41 of http://www.emc.com/emc-plus/rsa-labs/pkcs/files/h11300-wp-pkcs-1v2-2-rsa-cryptography-standard.pdf

    /****************************************************************************
     * Amazon Modifications: Copyright 2014 Amazon.com, Inc. or its affiliates. 
     * All Rights Reserved.
     *****************************************************************************
     * Copyright (c) 1998-2010 AOL Inc. 
     *
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at
     *
     *     http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     *
     ****************************************************************************
     * Convert PKCS#1 encoded private key into RSAPrivateCrtKeySpec.
     *
     * <p/>The ASN.1 syntax for the private key with CRT is
     *
     * <pre>
     * -- 
     * -- Representation of RSA private key with information for the CRT algorithm.
     * --
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version, 
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1) 
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL 
     * }
     * </pre>
     *
     * @param keyInPkcs1 PKCS#1 encoded key
     * @throws java.io.IOException
     */
    private static RSAPrivateCrtKeySpec newRSAPrivateCrtKeySpec(final byte[] keyInPkcs1) throws IOException {
        final DerParser parser = new DerParser(keyInPkcs1);

        final Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE) {
            throw new IllegalArgumentException("Invalid DER: not a sequence");
        }

        // Parse inside the sequence
        final DerParser p = sequence.getParser();

        p.read(); // Skip version
        final BigInteger modulus = p.read().getInteger();
        final BigInteger publicExp = p.read().getInteger();
        final BigInteger privateExp = p.read().getInteger();
        final BigInteger prime1 = p.read().getInteger();
        final BigInteger prime2 = p.read().getInteger();
        final BigInteger exp1 = p.read().getInteger();
        final BigInteger exp2 = p.read().getInteger();
        final BigInteger crtCoef = p.read().getInteger();

        return new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
    }

    /**
     * An ASN.1 TLV. The object is not parsed. It can
     * only handle integers and strings.
     *
     * @author zhang
     */
    static class Asn1Object {
        protected final int type;
        protected final int length;
        protected final byte[] value;
        protected final int tag;

        /**
         * Construct a ASN.1 TLV. The TLV could be either a
         * constructed or primitive entity.
         *
         * <p/>The first byte in DER encoding is made of following fields,
         * <pre>
         *-------------------------------------------------
         *|Bit 8|Bit 7|Bit 6|Bit 5|Bit 4|Bit 3|Bit 2|Bit 1|
         *-------------------------------------------------
         *|  Class    | CF  |     +      Type             |
         *-------------------------------------------------
         * </pre>
         * <ul>
         * <li>Class: Universal, Application, Context or Private
         * <li>CF: Constructed flag. If 1, the field is constructed.
         * <li>Type: This is actually called tag in ASN.1. It
         * indicates data type (Integer, String) or a construct
         * (sequence, choice, set).
         * </ul>
         *
         * @param tag Tag or Identifier
         * @param length Length of the field
         * @param value Encoded octet string for the field.
         */
        public Asn1Object(int tag, int length, byte[] value) {
            this.tag = tag;
            this.type = tag & 0x1F;
            this.length = length;
            this.value = value;
        }

        public int getType() {
            return type;
        }

        public int getLength() {
            return length;
        }

        public byte[] getValue() {
            return value;
        }

        public boolean isConstructed() {
            return (tag & DerParser.CONSTRUCTED) == DerParser.CONSTRUCTED;
        }

        /**
         * For constructed field, return a parser for its content.
         *
         * @return A parser for the construct.
         */
        public DerParser getParser() throws IOException {
            if (!isConstructed()) {
                throw new IOException("Invalid DER: can't parse primitive entity");
            }

            return new DerParser(value);
        }

        /**
         * Get the value as integer
         */
        public BigInteger getInteger() throws IOException {
            if (type != DerParser.INTEGER) {
                throw new IOException("Invalid DER: object is not integer");
            }

            return new BigInteger(value);
        }

        /**
         * Get value as string. Most strings are treated
         * as Latin-1.
         */
        public String getString() throws IOException {
            switch (type) {

                // Not all are Latin-1 but it's the closest thing
                case DerParser.NUMERIC_STRING:
                case DerParser.PRINTABLE_STRING:
                case DerParser.VIDEOTEX_STRING:
                case DerParser.IA5_STRING:
                case DerParser.GRAPHIC_STRING:
                case DerParser.ISO646_STRING:
                case DerParser.GENERAL_STRING:
                    return new String(value, "ISO-8859-1");

                case DerParser.BMP_STRING:
                    return new String(value, "UTF-16BE");

                case DerParser.UTF8_STRING:
                    return new String(value, "UTF-8");

                case DerParser.UNIVERSAL_STRING:
                    throw new IOException("Invalid DER: can't handle UCS-4 string");

                default:
                    throw new IOException("Invalid DER: object is not a string");
            }
        }
    }

    /**
     * A bare-minimum ASN.1 DER decoder, just having enough functions to decode
     * PKCS#1 private keys. Especially, it doesn't handle explicitly tagged types
     * with an outer tag.
     *
     * <p/>
     * This parser can only handle one layer. To parse nested constructs, get a new
     * parser for each layer using <code>Asn1Object.getParser()</code>.
     *
     * <p/>
     * There are many DER decoders in JRE but using them will tie this program to a
     * specific JCE/JVM.
     *
     * @author zhang
     */
    static class DerParser {
        // Classes
        public final static int UNIVERSAL = 0x00;
        public final static int APPLICATION = 0x40;
        public final static int CONTEXT = 0x80;
        public final static int PRIVATE = 0xC0;

        // Constructed Flag
        public final static int CONSTRUCTED = 0x20;

        // Tag and data types
        public final static int ANY = 0x00;
        public final static int BOOLEAN = 0x01;
        public final static int INTEGER = 0x02;
        public final static int BIT_STRING = 0x03;
        public final static int OCTET_STRING = 0x04;
        public final static int NULL = 0x05;
        public final static int OBJECT_IDENTIFIER = 0x06;
        public final static int REAL = 0x09;
        public final static int ENUMERATED = 0x0a;
        public final static int RELATIVE_OID = 0x0d;

        public final static int SEQUENCE = 0x10;
        public final static int SET = 0x11;

        public final static int NUMERIC_STRING = 0x12;
        public final static int PRINTABLE_STRING = 0x13;
        public final static int T61_STRING = 0x14;
        public final static int VIDEOTEX_STRING = 0x15;
        public final static int IA5_STRING = 0x16;
        public final static int GRAPHIC_STRING = 0x19;
        public final static int ISO646_STRING = 0x1A;
        public final static int GENERAL_STRING = 0x1B;

        public final static int UTF8_STRING = 0x0C;
        public final static int UNIVERSAL_STRING = 0x1C;
        public final static int BMP_STRING = 0x1E;

        public final static int UTC_TIME = 0x17;
        public final static int GENERALIZED_TIME = 0x18;

        protected final InputStream in;

        /**
         * Create a new DER decoder from an input stream.
         *
         * @param in
         *            The DER encoded stream
         */
        public DerParser(final InputStream in) throws IOException {
            this.in = in;
        }

        /**
         * Create a new DER decoder from a byte array.
         *
         * @param bytes the encoded bytes
         */
        public DerParser(final byte[] bytes) throws IOException {
            this(new ByteArrayInputStream(bytes));
        }

        /**
         * Read next object. If it's constructed, the value holds encoded content
         * and it should be parsed by a new parser from
         * <code>Asn1Object.getParser</code>.
         */
        public Asn1Object read() throws IOException {
            final int tag = in.read();

            if (tag == -1) {
                throw new IOException("Invalid DER: stream too short, missing tag");
            }

            final int length = getLength();

            final byte[] value = new byte[length];
            final int n = in.read(value);

            if (n < length) {
                throw new IOException("Invalid DER: stream too short, missing value");
            }

            return new Asn1Object(tag, length, value);
        }

        /**
         * Decode the length of the field. Can only support length encoding up to 4
         * octets.
         *
         * <p/>
         * In BER/DER encoding, length can be encoded in 2 forms,
         * <ul>
         * <li>Short form. One octet. Bit 8 has value "0" and bits 7-1 give the
         * length.
         * <li>Long form. Two to 127 octets (only 4 is supported here). Bit 8 of
         * first octet has value "1" and bits 7-1 give the number of additional
         * length octets. Second and following octets give the length, base 256,
         * most significant digit first.
         * </ul>
         *
         * @return The length as integer
         */
        private int getLength() throws IOException {

            final int i = in.read();

            if (i == -1) {
                throw new IOException("Invalid DER: length missing");
            }

            // A single byte short length
            if ((i & ~0x7F) == 0) return i;

            final int num = i & 0x7F;

            // We can't handle length longer than 4 bytes
            if (i >= 0xFF || num > 4) {
                throw new IOException("Invalid DER: length field too big (" + i + ")");
            }

            final byte[] bytes = new byte[num];
            final int n = in.read(bytes);

            if (n < num) {
                throw new IOException("Invalid DER: length too short");
            }

            return new BigInteger(1, bytes).intValue();
        }
    }
}
