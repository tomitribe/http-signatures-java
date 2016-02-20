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

package org.tomitribe.auth.signatures.jmh;

import com.sun.crypto.provider.SunJCE;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;
import sun.security.rsa.SunRsaSign;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.SECONDS)
@Fork(1)
@Threads(1)
@BenchmarkMode({Mode.Throughput})
@Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 1, time = 30000, timeUnit = TimeUnit.MILLISECONDS)
public class RsaVersusHmacMicroBenchmark {

    private final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private final SunRsaSign SUN_RSA_PROVIDER = new SunRsaSign();
    private final SunJCE SUN_JCE = new SunJCE();

    private final String RSA_ALGO = "SHA256withRSA";
    private final String HMAC_ALGO = "HmacSHA256";

    // generate the payload
    private final int[] PAYLOAD_SIZE = new int[]{2048, 4096, 8192};
    private final List<byte[]> PAYLOADS = new LinkedList<byte[]>() {{
        for (int i : PAYLOAD_SIZE) {
            add(RandomStringUtils.random(i).getBytes());
        }
    }};

    // generate all the key pairs
    private final int[] KEY_SIZE = new int[]{1024, 2048, 4096};
    private final List<KeyPair> RSA_KEYS = new LinkedList<KeyPair>() {{
        for (int i : KEY_SIZE) {
            try {
                final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BOUNCY_CASTLE_PROVIDER);
                generator.initialize(i, new SecureRandom());
                add(generator.generateKeyPair());

            } catch (final Exception e) {
                e.printStackTrace();
            }
        }
    }};
    private final List<SecretKey> HMAC_KEYS = new LinkedList<SecretKey>() {{
        for (int i : KEY_SIZE) {
            try {
                final KeyGenerator generator = KeyGenerator.getInstance(HMAC_ALGO, BOUNCY_CASTLE_PROVIDER);
                generator.init(i, new SecureRandom());
                add(generator.generateKey());

            } catch (final Exception e) {
                e.printStackTrace();
            }
        }
    }};

    // pre compute all the signatures
    private final List<List<byte[]>> RSA_SIGNATURES = new LinkedList<List<byte[]>>() {{
        for (final byte[] p : PAYLOADS) {
            final List<byte[]> l = new LinkedList<byte[]>() {{
                for (KeyPair k : RSA_KEYS) {
                    try {
                        final Signature signature = Signature.getInstance(RSA_ALGO, BOUNCY_CASTLE_PROVIDER);
                        signature.initSign(k.getPrivate());
                        signature.update(p);
                        add(signature.sign());

                    } catch (final Exception e) {
                        e.printStackTrace();
                    }
                }
            }};
            add(l);
        }
    }};
    private final List<List<byte[]>> HMAC_SIGNATURES = new LinkedList<List<byte[]>>() {{
        for (final byte[] p : PAYLOADS) {
            final List<byte[]> l = new LinkedList<byte[]>() {{
                for (SecretKey k : HMAC_KEYS) {
                    try {
                        final Mac mac = Mac.getInstance(HMAC_ALGO, BOUNCY_CASTLE_PROVIDER);
                        mac.init(k);
                        add(mac.doFinal(p));

                    } catch (final Exception e) {
                        e.printStackTrace();
                    }
                }
            }};
            add(l);
        }
    }};

    @Test
    public void listProvidersAndAlgo() {
        try {
            final Provider p[] = Security.getProviders();
            for (int i = 0; i < p.length; i++) {
                System.out.println(p[i]);
                for (Enumeration e = p[i].keys(); e.hasMoreElements(); )
                    System.out.println("\t" + e.nextElement());
            }

            System.out.println("---");
            System.out.println(BOUNCY_CASTLE_PROVIDER.getName());
            for (Enumeration e = BOUNCY_CASTLE_PROVIDER.keys(); e.hasMoreElements(); )
                System.out.println("\t" + e.nextElement());
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static void main(final String[] args) throws Exception {
        final Options options = new OptionsBuilder()
                .verbosity(VerboseMode.NORMAL)
                .include(".*" + RsaVersusHmacMicroBenchmark.class.getSimpleName() + ".*")
                .build();

        new Runner(options).run();
    }

    // Generated - do not update
    // RSA
    @Benchmark
    public byte[] rsa_sign_payload8192_with_key2048_BOUNCY_CASTLE_PROVIDER() throws Exception {
        final Signature signature = Signature.getInstance(RSA_ALGO, BOUNCY_CASTLE_PROVIDER);
        signature.initSign(RSA_KEYS.get(1).getPrivate());
        signature.update(PAYLOADS.get(2));
        final byte[] actual = signature.sign();
        Assert.assertArrayEquals(RSA_SIGNATURES.get(2).get(1), actual);
        return actual;
    }

    @Benchmark
    public void rsa_verify_payload8192_with_key2048_BOUNCY_CASTLE_PROVIDER(final Blackhole bh) throws Exception {
        final Signature signature = Signature.getInstance(RSA_ALGO, BOUNCY_CASTLE_PROVIDER);
        signature.initVerify(RSA_KEYS.get(1).getPublic());
        signature.update(PAYLOADS.get(2));
        bh.consume(signature.verify(RSA_SIGNATURES.get(2).get(1)));
    }

    @Benchmark
    public byte[] rsa_sign_payload8192_with_key2048_SUN_RSA_PROVIDER() throws Exception {
        final Signature signature = Signature.getInstance(RSA_ALGO, SUN_RSA_PROVIDER);
        signature.initSign(RSA_KEYS.get(1).getPrivate());
        signature.update(PAYLOADS.get(2));
        final byte[] actual = signature.sign();
        Assert.assertArrayEquals(RSA_SIGNATURES.get(2).get(1), actual);
        return actual;
    }

    @Benchmark
    public void rsa_verify_payload8192_with_key2048_SUN_RSA_PROVIDER(final Blackhole bh) throws Exception {
        final Signature signature = Signature.getInstance(RSA_ALGO, SUN_RSA_PROVIDER);
        signature.initVerify(RSA_KEYS.get(1).getPublic());
        signature.update(PAYLOADS.get(2));
        bh.consume(signature.verify(RSA_SIGNATURES.get(2).get(1)));
    }

    ///// HMAC
    @Benchmark
    public byte[] hmac_sign_payload8192_with_key2048_BOUNCY_CASTLE_PROVIDER() throws Exception {
        final Mac mac = Mac.getInstance(HMAC_ALGO, BOUNCY_CASTLE_PROVIDER);
        mac.init(HMAC_KEYS.get(1));
        final byte[] actual = mac.doFinal(PAYLOADS.get(2));
        Assert.assertArrayEquals(HMAC_SIGNATURES.get(2).get(1), actual);
        return actual;
    }
    @Benchmark
    public byte[] hmac_sign_payload8192_with_key2048_SUN_JCE() throws Exception {
        final Mac mac = Mac.getInstance(HMAC_ALGO, SUN_JCE);
        mac.init(HMAC_KEYS.get(1));
        final byte[] actual = mac.doFinal(PAYLOADS.get(2));
        Assert.assertArrayEquals(HMAC_SIGNATURES.get(2).get(1), actual);
        return actual;
    }
    // End generated
}
