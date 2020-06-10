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

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.tomitribe.auth.signatures.Join.join;

public class SignatureTest {

    @Test
    public void validSignature() {
        new Signature("somekey", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullKey() {
        new Signature(null, SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));
    }

    @Test
    public void nullSignature() {
        new Signature("somekey", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, null, Arrays.asList("date", "accept"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullAlgorithm() {
        new Signature("somekey", SigningAlgorithm.HS2019.getAlgorithmName(), (String) null, null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullSigningAlgorithm() {
        new Signature("somekey", null, "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));
    }

    /**
     * Invalid (created) field, the value must be a number, not a string.
     */
    @Test(expected = InvalidCreatedFieldException.class)
    public void signatureCreatedFieldAsString() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=\"1591763110\"," +
                "headers=\"(created)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }


    /**
     * The signature is invalid because the (created) field is in the future.
     */
    @Test(expected = InvalidCreatedFieldException.class)
    public void signatureCreatedInTheFuture() throws Exception {
        long created = (System.currentTimeMillis() / 1000L) + 3600;
        String authorization = String.format("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=%d," +
                "headers=\"(created)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"", created);
        Signature.fromString(authorization, null);
    }

    /**
     * The signature is invalid because the (expires) field is in the past.
     */
    @Test(expected = InvalidExpiresFieldException.class)
    public void signatureExpiresInThePast() throws Exception {
        double expires = (System.currentTimeMillis() / 1000.0) - 3600;
        String authorization = String.format("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "expires=%f," +
                "headers=\"(expires)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"", expires);
        Signature.fromString(authorization, null);
    }

    /**
     * The signature has been created slightly in the future.
     * In practice, this is most likely due to a time skew between the client and server.
     */
    @Test
    public void signatureCreatedSlightlyInTheFuture() throws Exception {
        long created = (System.currentTimeMillis() / 1000L) + 5;
        String authorization = String.format("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=%d," +
                "headers=\"(created)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"", created);
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid (created) field, the value must be a number, not a string.
     */
    @Test(expected = InvalidCreatedFieldException.class)
    public void signatureCreatedFieldIntegerTooLarge() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=15917631101724387234723847238492374892374283947289472398472834," +
                "headers=\"(created)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid (created) field, the value must be an integer, decimal values are not supported.
     */
    @Test(expected = InvalidCreatedFieldException.class)
    public void signatureCreatedFieldDecimalValue() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=1591763110.123," +
                "headers=\"(created)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid (expires) field, the value must be a number, not a string.
     */
    @Test(expected = InvalidExpiresFieldException.class)
    public void signatureExpiresFieldAsString() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "expires=\"159176.3110\"," +
                "headers=\"(expires)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid (expires) field, the value must be a parseable number
     */
    @Test(expected = InvalidExpiresFieldException.class)
    public void signatureExpiresFieldInvalidNumber() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "expires=\"159176..3110\"," +
                "headers=\"(expires)\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid keyId field, the value must be a double-quoted string.
     */
    @Test(expected = MissingKeyIdException.class)
    public void signatureInvalidKeyIdFormat() throws Exception {
        String authorization = "Signature keyId=hmac-key-1,algorithm=\"hmac-sha256\"," +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid keyId field, the value must be a double-quoted string, not a number.
     */
    @Test(expected = MissingKeyIdException.class)
    public void signatureInvalidKeyIdFormatNumberr() throws Exception {
        String authorization = "Signature keyId=1123,algorithm=\"hmac-sha256\"," +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }
    
    /**
     * Invalid algorithm field, the value must be a double-quoted string.
     */
    @Test(expected = MissingAlgorithmException.class)
    public void signatureInvalidAlgorithmFormat() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=256," +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";
        Signature.fromString(authorization, null);
    }

    /**
     * Invalid signature field, the value must be a double-quoted string.
     */
    @Test(expected = MissingSignatureException.class)
    public void signatureInvalidSignatureFormat() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                ",signature=1234";
        Signature.fromString(authorization, null);
    }
    
    @Test
    public void nullHeaders() {
        final Signature signature = new Signature("somekey", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList());
        assertEquals(1, signature.getHeaders().size()); // should contain at least the Date which is required
        assertEquals("date", signature.getHeaders().get(0).toLowerCase());
    }


    @Test
    public void roundTripTest() throws Exception {
        final Signature expected = new Signature("somekey", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));
        final Signature actual = Signature.fromString(expected.toString(), null);

        assertSignature(expected, actual);
    }

    @Test
    public void testFromString() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", signature.getSignature());
        assertEquals("(request-target)\n" +
                "host\n" +
                "date\n" +
                "digest\n" +
                "content-length", join("\n", signature.getHeaders()));
    }

    /**
     * Same as testFromString, but the algorithm is set to 'hs2019',
     * @throws Exception
     */
    @Test
    public void testFromStringHmacSha256() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hs2019\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        final Signature signature = Signature.fromString(authorization, Algorithm.HMAC_SHA256);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", signature.getSignature());
        assertEquals("(request-target)\n" +
                "host\n" +
                "date\n" +
                "digest\n" +
                "content-length", join("\n", signature.getHeaders()));
    }

    @Test
    public void testFromStringWithLdapDNKeyId() throws Exception {
        String authorization = "Signature keyId=\"UID=jsmith,DC=example,DC=net\",algorithm=\"hmac-sha256\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("UID=jsmith,DC=example,DC=net", signature.getKeyId());
    }

    /**
     * Authorization header parameters (keyId, algorithm, headers, signature)
     * may legally not include 'headers'
     */
    @Test
    public void noHeaders() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"";

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals("date", join("\n", signature.getHeaders()));
    }

    /**
     * Order in headers parameter must be retained
     */
    @Test
    public void headersOrder() throws Exception {
        String authorization = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "headers=\"one two three four five six\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals("one\n" +
                "two\n" +
                "three\n" +
                "four\n" +
                "five\n" +
                "six", join("\n", signature.getHeaders()));
    }

    /**
     * Signature validity fields (created) and (expires).
     */
    @Test
    public void signatureCreatedAndExpiresFields() throws Exception {
        long created = System.currentTimeMillis() / 1000L;
        double expires = System.currentTimeMillis() / 1000.0 + 3600;
        String authorization = String.format("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "created=%d,expires=%f," +
                "headers=\"(request-target) (created) (expires) one two\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"", created, expires);

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals(
                "(request-target)\n" +
                "(created)\n" +
                "(expires)\n" +
                "one\n" +
                "two", join("\n", signature.getHeaders()));
        assertEquals((Long)created, signature.getSignatureCreationTime());
        assertEquals((Double)expires, signature.getSignatureExpirationTime());
    }

    @Test
    public void noSignaturePrefix() throws Exception {
        String authorization = "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"";

        final Signature signature = Signature.fromString(authorization, null);

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals("date", join("\n", signature.getHeaders()));
    }

    /**
     * Authorization header parameters (keyId, algorithm, headers, signature)
     * may have whitespace between them
     */
    @Test
    public void whitespaceTolerance() throws Exception {
        String authorization = "  \nkeyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"  \n";

        Signature signature = Signature.fromString(authorization, null);
        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals("date", join("\n", signature.getHeaders()));

        signature = Signature.fromString(authorization, Algorithm.HMAC_SHA256);
        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("Base64(HMAC-SHA256(signing string))", signature.getSignature());
        assertEquals("date", join("\n", signature.getHeaders()));
    }

    /**
     * Authorization header parameters (keyId, algorithm, headers, signature)
     * can be in any order
     */
    @Test
    public void orderTolerance() throws Exception {

        final Signature expected = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept"));

        final List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\""
        );

        for (int tries = 10; tries > 0; tries--) {
            Collections.shuffle(input);

            final String authorization = join(",", input);

            parseAndAssert(authorization, expected);
        }
    }

    /**
     * Headers supplied in the constructor should be lowercased
     * Algorithm supplied in the constructor should be lowercased
     */
    @Test
    public void caseNormalization() throws Exception {

        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hMaC-ShA256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("dAte", "aCcEpt"));

        assertEquals("hmac-key-1", signature.getKeyId());
        assertEquals("hmac-sha256", signature.getAlgorithm().toString());
        assertEquals("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", signature.getSignature());
        assertEquals("date\naccept", join("\n", signature.getHeaders()));
    }

    /**
     * 2.2.  Ambiguous Parameters
     * <p/>
     * If any of the parameters listed above are erroneously duplicated in
     * the associated header field, then the last parameter defined MUST be
     * used.  Any parameter that is not recognized as a parameter, or is not
     * well-formed, MUST be ignored.
     */
    @Test
    public void ambiguousParameters() throws Exception {

        final Signature expected = new Signature("hmac-key-3", SigningAlgorithm.HS2019.getAlgorithmName(), "dsa-sha1", null, "DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=", Arrays.asList("date"));

        final List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "keyId=\"hmac-key-3\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept content-length\"",
                "algorithm=\"dsa-sha1\"",
                "headers=\"date\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"",
                "signature=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        final String authorization = join(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void parameterCaseTolerance() throws Exception {

        final Signature expected = new Signature("hmac-key-3", SigningAlgorithm.HS2019.getAlgorithmName(), "rsa-sha256", null, "DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=", Arrays.asList("date"));

        final List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "KeyId=\"hmac-key-3\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept content-length\"",
                "aLgorithm=\"rsa-sha256\"",
                "headers=\"date\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"",
                "SIGNATURE=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        final String authorization = join(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void unknownParameters() throws Exception {

        final Signature expected = new Signature("hmac-key-3", SigningAlgorithm.HS2019.getAlgorithmName(), "rsa-sha256", null, "PIft5ByT/Nr5RWvB+QLQRyFAvbGmauCOE7FTL0tI+Jg=", Arrays.asList("date"));

        final List<String> input = Arrays.asList(
                "scopeId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "keyId=\"hmac-key-3\"",
                "precision=\"hmac-sha256\"",
                "algorithm=\"rsa-sha256\"",
                "topics=\"date accept content-length\"",
                "headers=\"date\"",
                "signature=\"PIft5ByT/Nr5RWvB+QLQRyFAvbGmauCOE7FTL0tI+Jg=\"",
                "signage=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        final String authorization = join(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void trailingCommaTolerance() throws Exception {
        String authorization = "" +
                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"date accept\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"" +
                " , ";

        parseAndAssert(authorization, new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", Arrays.asList("date", "accept")));
    }

    @Test
    public void testToString() throws Exception {

        final Signature signature = new Signature("hmac-key-1", SigningAlgorithm.HS2019.getAlgorithmName(), "hmac-sha256", null, "Base64(HMAC-SHA256(signing string))", Arrays.asList("(request-target)", "host", "date", "digest", "content-length"));

        String authorization = "Signature keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"Base64(HMAC-SHA256(signing string))\"";

        assertEquals(authorization, signature.toString());
    }


    /**
     * Parsing should only ever throw SignatureHeaderFormatException
     * <p/>
     * We want to avoid NullPointerException, StringIndexOutOfBoundsException and
     * any other exception that might result.
     */
    @Test
    public void throwsAuthorizationException() {

        final Random random = new Random();

        final StringBuilder authorization = new StringBuilder("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        while (authorization.length() > 0) {

            // Delete a random character and parse again
            authorization.deleteCharAt(random.nextInt(authorization.length()));

            try {

                Signature.fromString(authorization.toString(), null);

            } catch (AuthenticationException e) {
                // pass
            } catch (Throwable e) {
                fail("SignatureHeaderFormatException should be the only possible exception type: caught " + e.getClass().getName());
            }
        }
    }

    @Test(expected = MissingKeyIdException.class)
    public void missingKeyId() {
        String authorization = "" +
//                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        Signature.fromString(authorization, null);
    }

    @Test(expected = MissingAlgorithmException.class)
    public void missingAlgorithm() {
        String authorization = "" +
                "keyId=\"hmac-key-1\"," +
//                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        Signature.fromString(authorization, null);
    }


    @Test(expected = MissingSignatureException.class)
    public void missingSignature() {
        String authorization = "" +
                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"";
//                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        Signature.fromString(authorization, null);
    }


    private static void parseAndAssert(final String authorization, final Signature expected) {
        final Signature actual = Signature.fromString(authorization, null);
        assertSignature(expected, actual);
    }

    private static void assertSignature(Signature expected, Signature actual) {
        assertEquals(expected.getKeyId(), actual.getKeyId());
        assertEquals(expected.getAlgorithm(), actual.getAlgorithm());
        assertEquals(expected.getSignature(), actual.getSignature());
        assertEquals(join("\n", expected.getHeaders()), join("\n", actual.getHeaders()));
    }
}
