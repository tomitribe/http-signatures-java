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
import java.security.Key;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class VerifierTest extends Assert {

    @Test(expected = IllegalStateException.class)
    public void validVerifier() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Verifier(key, signature);
    }

    @Test(expected = NullPointerException.class)
    public void nullKey() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        new Verifier(null, signature);
    }

    @Test(expected = NullPointerException.class)
    public void nullSignature() {
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Verifier(key, null);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void unsupportedAlgorithm() {
        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "should fail because of this", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Verifier(key, signature);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void algoNotImplemented() {
        final Provider p = new Provider("Tribe", 1.0, "Only for mock") {{
            clear();
        }};

        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, Arrays.asList("content-length", "host", "date", "(request-target)"));
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        new Verifier(key, signature, p);
    }

    /**
     * Validates Signature.fromString() can be invoked with a specific algorithm.
     * If the algorithm argument matches the 'algorithm' field in the Authorization header,
     * no exception should be thrown.
     * @throws Exception
     */
    public void testParseAuthorizationWithValidAlgorithm() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
        final Signature signature = Signature.fromString(authorization, Algorithm.HMAC_SHA256);
        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

        final String method = "GET";
        final String uri = "/foo/Bar";
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");
        final boolean verifies = verifier.verify(method, uri, headers);
        assertTrue(verifies);
    }

    /**
     * Validates Signature.fromString() can be invoked with a specific algorithm.
     * If the algorithm argument does NOT match the 'algorithm' field in the Authorization header,
     * an exception should be thrown.
     * @throws Exception
     */
    @Test(expected = UnparsableSignatureException.class)
    public void testParseAuthorizationWithConflictingAlgorithm() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
        Signature.fromString(authorization, Algorithm.HMAC_SHA512);
    }

    /**
     * Validates Signature.fromString() must have a non-null 'algorithm' argument when
     * the 'algorithm' field in the HTTP 'Authorization' header is set to 'hs2019'.
     * This is because the 'Authorization' header is not sufficient to identify the detailed
     * cryptographic algorithm.
     * @throws Exception
     */
    @Test(expected = UnparsableSignatureException.class)
    public void testParseAuthorizationHs2019MissingAlgorithm() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hs2019\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
        Signature.fromString(authorization, null);
    }

    @Test
    public void testVerifyAndValidateDates() throws Exception {
        // Create a signature with a short validation duration.
        // If the signature is verified immediately, the validation should pass.
        // If the signature is verified after the expiration time, the validation should fail.
        final long maxValidity = 1 * 1000L;

        final Signature inputSignature = new Signature("hmac-key-1",
                SigningAlgorithm.HS2019, Algorithm.HMAC_SHA256, null, null,
                Arrays.asList("content-length", "host", "date", "(request-target)", "(created)", "(expires)"),
                maxValidity, System.currentTimeMillis(), System.currentTimeMillis() + maxValidity);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, inputSignature);

        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Host", "example.org");
        headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");

        // Assert the Signing String
        final String expectedSigningStringRegex = "" +
                "content-length: 18\n" +
                "host: example.org\n" +
                "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                "\\(request-target\\): get \\/foo\\/Bar\n" +
                "\\(created\\): [\\d]+\n" +
                "\\(expires\\): [\\d]+\\.?[\\d]*";
        final Pattern regex = Pattern.compile(expectedSigningStringRegex, Pattern.MULTILINE);
        final String signingString = signer.createSigningString("GET", "/foo/Bar", headers);
        assertTrue(regex.matcher(signingString).find());

        // Assert the signature
        final Signature signature = signer.sign("GET", "/foo/Bar", headers);

        final String authorization = signature.toString();
        assertTrue(authorization.contains("(created)"));
        assertTrue(authorization.contains("(expires)"));
        assertTrue(authorization.contains("created="));
        assertTrue(authorization.contains("expires="));

        // Assert the signature verification.
        final Signature parsedSignature = Signature.fromString(authorization, Algorithm.HMAC_SHA256);
        assertNotNull(parsedSignature.getSignatureCreationTimeMilliseconds());
        assertNotNull(parsedSignature.getSignatureExpirationTimeMilliseconds());
        assertNotNull(parsedSignature.getSignatureCreation());
        assertNotNull(parsedSignature.getSignatureExpiration());

        final Verifier verifier = new Verifier(key, parsedSignature);
        final boolean verifies = verifier.verify("GET", "/foo/Bar", headers);
        assertTrue(verifies);

        // Sleep a bit, this will cause the signature to expire, then verify
        // the signature again, this time it should fail.
        Thread.sleep(maxValidity);
        final Exception exception = assertThrows(InvalidExpiresFieldException.class, () -> {
            verifier.verify("GET", "/foo/Bar", headers);
        });
        assertEquals("Signature has expired", exception.getMessage());
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
    public void testVerify() throws Exception {

        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
        final Signature signature = Signature.fromString(authorization, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

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
            final boolean verifies = verifier.verify(method, uri, headers);
            assertTrue(verifies);
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
            final boolean verifies = verifier.verify(method, uri, headers);
            assertFalse(verifies);
        }

        { // only Digest changed.  not part of the signature, should have no effect
            final String method = "GET";
            final String uri = "/foo/Bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final boolean verifies = verifier.verify(method, uri, headers);
            assertTrue(verifies);
        }

        { // uri changed.  should get a different signature
            final String method = "GET";
            final String uri = "/foo/bar";
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Host", "example.org");
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");
            final boolean verifies = verifier.verify(method, uri, headers);
            assertFalse(verifies);
        }
    }

    @Test
    public void defaultHeaderList() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"WbB9VXuVdRt1LKQ5mDuT+tiaChn8R7WhdAWAY1lhKZQ=\"";
        final Signature signature = Signature.fromString(authorization, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

        { // just date should be required
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

            final boolean verifies = verifier.verify("GET", "/foo/Bar", headers);
            assertTrue(verifies);
        }

        { // adding other headers shouldn't matter
            final Map<String, String> headers = new HashMap<String, String>();
            headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
            headers.put("Content-Type", "application/json");
            headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
            headers.put("Accept", "*/*");
            headers.put("Content-Length", "18");

            final boolean verifies = verifier.verify("GET", "/foo/Bar", headers);
            assertTrue(verifies);
        }
    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingDefaultHeader() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"\",signature=\"WbB9VXuVdRt1LKQ5mDuT+tiaChn8R7WhdAWAY1lhKZQ=\"";
        final Signature signature = Signature.fromString(authorization, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

        final Map<String, String> headers = new HashMap<String, String>();
        verifier.verify("GET", "/foo/Bar", headers);
    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingExplicitHeader() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"date accept\",signature=\"WbB9VXuVdRt1LKQ5mDuT+tiaChn8R7WhdAWAY1lhKZQ=\"";
        final Signature signature = Signature.fromString(authorization, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("Date", "Tue, 07 Jun 2014 20:51:36 GMT");
        verifier.verify("GET", "/foo/Bar", headers);
    }

    @Test
    public void testVerify1() throws Exception {
        final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
        final Signature signature = Signature.fromString(authorization, null);

        final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
        final Verifier verifier = new Verifier(key, signature);

        //final Signature signature = new Signature("hmac-key-1", "hmac-sha256", null, "content-length", "host", "date", "(request-target)");

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

            assertEquals(signingString, verifier.createSigningString("GET", "/foo/Bar", headers));
        }

    }

    @Test
    public void testCreateSingingString() throws Exception {
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

            final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"(request-target) host date digest content-length\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
            final Signature signature = Signature.fromString(authorization, null);

            final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
            final Verifier verifier = new Verifier(key, signature);

            final String string = verifier.createSigningString(method, uri, headers);
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

            final String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";
            final Signature signature = Signature.fromString(authorization, null);

            final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
            final Verifier verifier = new Verifier(key, signature);

            final String string = verifier.createSigningString(method, uri, headers);
            assertEquals("content-length: 18\n" +
                            "host: example.org\n" +
                            "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                            "(request-target): get /foo/Bar"
                    , string);
        }
    }


}
