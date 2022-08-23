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

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SignerTest extends Assert {

    @Test
    public void validSigner() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, signature);
    }

    @Test(expected = NullPointerException.class)
    public void nullKey() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        new Signer(null, signature);
    }

    @Test(expected = NullPointerException.class)
    public void nullSignature() {
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, null);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void unsupportedAlgorithm() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "should fail because of this", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, signature);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void unsupportedSigningAlgorithm() {
        final Signature signature = new Signature("hmac-key-1", "unsupported signing algorithm", "hmac-sha256", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void conflictingSigningAlgorithm() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.RSA_SHA256.getAlgorithmName(), "hmac-sha256", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, signature);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void algoNotImplemented() {
        final Provider p = new Provider("Tribe", 1.0, "Only for mock") {{
            clear();
        }};

        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Signer(key, signature, p);
    }

    /**
     * It is an intentional part of the design that the same Signer instance
     * can be reused on several HTTP Messages in a multi-threaded fashion
     * <p/>
     * Reuse is tested here
     * <p/>
     * TODO test threading
     */
    @Test
    public void testSign() throws Exception {

        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature, Clock.fixed(Instant.ofEpochMilli(123456789l), ZoneId.systemDefault()));

        {
            final String method = "GET";
            final String uri = "/foo/Bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final Signature signed = signer.sign(method, uri, headers);
            assertEquals("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", signed.getSignature());
            assertEquals("Signature keyId=\"hmac-key-1\",created=123456,algorithm=\"hs2019\"," +
                        "headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"", signed.toString());
        }

        { // method changed.  should get a different signature
            final String method = "PUT";
            final String uri = "/foo/Bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final Signature signed = signer.sign(method, uri, headers);
            assertEquals("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=", signed.getSignature());
            assertEquals("Signature keyId=\"hmac-key-1\",created=123456,algorithm=\"hs2019\"," +
                        "headers=\"content-length host date (request-target)\",signature=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\"", signed.toString());
        }

        { // only Digest changed.  not part of the signature, should have no effect
            final String method = "PUT";
            final String uri = "/foo/Bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final Signature signed = signer.sign(method, uri, headers);
            assertEquals("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=", signed.getSignature());
            assertEquals("Signature keyId=\"hmac-key-1\",created=123456,algorithm=\"hs2019\"," +
                        "headers=\"content-length host date (request-target)\",signature=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\"", signed.toString());
        }

        { // uri changed.  should get a different signature
            final String method = "PUT";
            final String uri = "/foo/bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final Signature signed = signer.sign(method, uri, headers);
            assertEquals("IWTDxmOoEJI67YxY3eDIRzxrsAtlYYCuGZxKlkUSYdA=", signed.getSignature());
            assertEquals("Signature keyId=\"hmac-key-1\",created=123456,algorithm=\"hs2019\"," +
                        "headers=\"content-length host date (request-target)\",signature=\"IWTDxmOoEJI67YxY3eDIRzxrsAtlYYCuGZxKlkUSYdA=\"", signed.toString());
        }
    }

    @Test
    public void defaultHeaderList() throws Exception {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256",
                null, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);

        { // just date should be required
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

            final Signature signed = signer.sign("GET", "/foo/Bar", headers);
            assertEquals("WbB9VXuVdRt1LKQ5mDuT+tiaChn8R7WhdAWAY1lhKZQ=", signed.getSignature());
        }

        { // one second later
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Date", "Tue, 07 Jun 2014 20:51:36 GMT");

            final Signature signed = signer.sign("GET", "/foo/Bar", headers);
            assertEquals("kRkh0bV1wKZSXBgexUB+zlPU88/za5K/gk/F0Aikg7Q=", signed.getSignature());
        }

        { // adding other headers shouldn't matter
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Date", "Tue, 07 Jun 2014 20:51:36 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");

            final Signature signed = signer.sign("GET", "/foo/Bar", headers);
            assertEquals("kRkh0bV1wKZSXBgexUB+zlPU88/za5K/gk/F0Aikg7Q=", signed.getSignature());
        }
    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingDefaultHeader() throws Exception {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);

        final Map<String, String> headers = new HashMap<String, String>();
        signer.sign("GET", "/foo/Bar", headers);
    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingExplicitHeader() throws Exception {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("date", "accept"));

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);

        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Date", "Tue, 07 Jun 2014 20:51:36 GMT");
        signer.sign("GET", "/foo/Bar", headers);
    }

    @Test
    public void testSign1() throws Exception {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);

        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");

        { // Assert the Signing String

            final String signingString = "" +
                    "content-length: 18\n" +
                    "host: example.org\n" +
                    "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                    "(request-target): get /foo/Bar";

            assertEquals(signingString, signer.createSigningString("GET", "/foo/Bar", headers));
        }

        { // Assert the signature

            final String encodedSignature = signer.sign("GET", "/foo/Bar", headers).getSignature();

            assertEquals("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", encodedSignature);
        }
    }

    /**
     * Test the 'algorithm' field in the 'Authorization' header has the expected value.
     *
     * @throws Exception when a unit test fails.
     */
    @Test
    public void testAlgorithFieldInAuthorizationHeader() throws Exception {
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");

        final String ecPrivateKeyPem = "" +
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAwMH6qcFB3MyllyHKe\n" +
                "4mqAFWS2gbD4XWzKtCnSmj2b1A==\n" +
                "-----END EC PRIVATE KEY-----\n";

        final String rsaPrivateKeyPem = "" +
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF\n" +
                "NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\n" +
                "UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB\n" +
                "AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\n" +
                "QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK\n" +
                "kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\n" +
                "f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u\n" +
                "412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\n" +
                "mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7\n" +
                "kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA\n" +
                "gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW\n" +
                "G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI\n" +
                "7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n" +
                "-----END RSA PRIVATE KEY-----\n";

        {
            // Create a signature with the RSA SHA-256 algorithm.
            // The signing algorithm is set to RSA_SHA256, hence the value of the
            // 'algorithm' field in the Authorization header must be 'rsa-sha256'.
            final Signature signature = new Signature("my-key",
                    SigningAlgorithm.RSA_SHA256,
                    Algorithm.RSA_SHA256, null, null,
                    Arrays.asList("(request-target)", "host", "date", "digest", "content-length"));
            final PrivateKey privateKey = PEM.readPrivateKey(new ByteArrayInputStream(rsaPrivateKeyPem.getBytes()));
            final Signer signer = new Signer(privateKey, signature);
            final Signature s = signer.sign("POST", "", headers);
            assertTrue(s.toString().contains("algorithm=\"rsa-sha256\""));
        }
        {
            // Create a signature with the RSA SHA-256 algorithm.
            // But this time the signing algorithm is set to HS2019, hence the value of the
            // 'algorithm' field in the Authorization header must be 'hs2019'.
            // The actual value of the algorithm is not serialized on the wire, the server
            // must derive the value from the keyId (out-of-band).
            final Signature signature = new Signature("my-key",
                    SigningAlgorithm.HS2019,
                    Algorithm.RSA_SHA256, null, null,
                    Arrays.asList("(request-target)", "host", "date", "digest", "content-length"));
            final PrivateKey privateKey = PEM.readPrivateKey(new ByteArrayInputStream(rsaPrivateKeyPem.getBytes()));
            final Signer signer = new Signer(privateKey, signature);
            final Signature s = signer.sign("POST", "", headers);
            assertTrue(s.toString().contains("algorithm=\"hs2019\""));
        }
        {
            // Create a signature with the ECDSA SHA256 algorithm.
            // The signing algorithm is set to HS2019, hence the value of the
            // 'algorithm' field in the Authorization header must be 'hs2019'.
            // The actual value of the algorithm is not serialized on the wire, the server
            // must derive the value from the keyId (out-of-band).
            final Signature signature = new Signature("my-key",
                    SigningAlgorithm.HS2019,
                    Algorithm.ECDSA_SHA256, null, null,
                    Arrays.asList("(request-target)", "host", "date", "digest", "content-length"));
            final PrivateKey privateKey = PEM.readPrivateKey(new ByteArrayInputStream(ecPrivateKeyPem.getBytes()));
            final Signer signer = new Signer(privateKey, signature);
            final Signature s = signer.sign("POST", "", headers);
            assertTrue(s.toString().contains("algorithm=\"hs2019\""));
        }
    }

    @Test
    public void testCreateSigningString() throws Exception {
        {
            final String method = "POST";
            final String uri = "/foo";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");

            final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("(request-target)", "host", "date", "digest", "content-length"));
            final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
            final Signer signer = new Signer(key, signature);

            final String string = signer.createSigningString(method, uri, headers);
            assertEquals("(request-target): post /foo\n" +
                    "host: example.org\n" +
                    "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                    "digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n" +
                    "content-length: 18", string);
        }

        {
            final String method = "GET";
            final String uri = "/foo/Bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");

            final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("content-length", "host", "date", "(request-target)"));
            final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
            final Signer signer = new Signer(key, signature);

            final String string = signer.createSigningString(method, uri, headers);
            assertEquals("content-length: 18\n" +
                            "host: example.org\n" +
                            "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                            "(request-target): get /foo/Bar"
                    , string);
        }
    }


}
