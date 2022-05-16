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

import java.security.spec.AlgorithmParameterSpec;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Signature {

    /**
     * REQUIRED.  The `keyId` field is an opaque string that the server can
     * use to look up the component they need to validate the signature.  It
     * could be an SSH key fingerprint, a URL to machine-readable key data,
     * an LDAP DN, etc.  Management of keys and assignment of `keyId` is out
     * of scope for this document.
     */
    private final String keyId;

    /**
     * RECOMMENDED.  The `signingAlgorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms and MUST NOT be marked "deprecated".
     *
     * Verifiers MUST determine the signature's Algorithm from the keyId parameter
     * rather than from algorithm. If algorithm is provided and differs from or
     * is incompatible with the algorithm or key material identified by keyId
     * (for example, algorithm has a value of rsa-sha256 but keyId identifies
     * an EdDSA key), then implementations MUST produce an error.
     *
     * https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/
     */
    private final SigningAlgorithm signingAlgorithm;

    /**
     * REQUIRED.  The `algorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms and MUST NOT be marked "deprecated".
     */
    private final Algorithm algorithm;

    /**
     * REQUIRED.  The `signature` parameter is a base 64 encoded digital
     * signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
     * client uses the `algorithm` and `headers` signature parameters to
     * form a canonicalized `signing string`.  This `signing string` is then
     * signed with the key associated with `keyId` and the algorithm
     * corresponding to `algorithm`.  The `signature` parameter is then set
     * to the base 64 encoding of the signature.
     *
     * Signing: this field is calculated from the input data.
     * Verification: this field is parsed from the signature field in the
     * Authorization header.
     */
    private final String signature;

    /**
     * OPTIONAL.  The `headers` parameter is used to specify the list of
     * HTTP headers included when generating the signature for the message.
     * If specified, it should be a lowercased, quoted list of HTTP header
     * fields, separated by a single space character.  If not specified,
     * implementations MUST operate as if the field were specified with a
     * single value, the `Date` header, in the list of HTTP headers.  Note
     * that the list order is important, and MUST be specified in the order
     * the HTTP header field-value pairs are concatenated together during
     * signing.
     */
    private final List<String> headers;

    /**
     * OPTIONAL.  The `parameterSpec` is used to specify the cryptographic
     * parameters. Some cryptographic algorithm such as RSASSA-PSS
     * require parameters.
     */
    private final AlgorithmParameterSpec parameterSpec;

    /**
     * OPTIONAL. The configurable signature's maximum validation duration, in milliseconds.
     * This field is applicable when the signed headers include '(expires)'.
     * In that case, the value of the '(expires)' field is calculated by adding
     * maxSignatureValidityDuration to the timestamp of the signature creation time.
     *
     * This field is used to derive the signature expiration time when a cryptographic signature
     * is generated.
     */
    private final Long maxSignatureValidityDuration;

    /**
     * The signature's Creation Time, in milliseconds since the epoch.
     *
     * This field is set at the time the cryptographic signature is generated, or when
     * the 'Authorization' header is parsed.
     */
    private final Long signatureCreatedTime;

    /**
     * The signature's Expiration Time, in milliseconds since the epoch.
     *
     * This field is set at the time the cryptographic signature is generated, or when
     * the 'Authorization' header is parsed.
     */
    private final Long signatureExpiresTime;

    /**
     * Regular expression pattern for fields present in the Authorization field.
     * Fields value may be double-quoted strings, e.g. algorithm="hs2019"
     * Some fields may be numerical values without double-quotes, e.g. created=123456
     * Fields that are numerical values with digits are formatted regarding the current Locale. The char used can be a "." (dot) or a "," coma.
     */
    private static final Pattern RFC_2617_PARAM = Pattern
            .compile("(?<key>\\w+)=((\"(?<stringValue>[^\"]*)\")|(?<numberValue>\\d+[.,]?\\d*))");

    /**
     * The maximum time skew between the client and the server.
     * This is used to validate the (created) and (expires) fields in the HTTP signature.
     */
    public static long maxTimeSkewInMilliseconds = 30 * 1000L;

    /**
     * Construct a signature configuration instance with the specified keyId, algorithm and HTTP headers.
     *
     * @param keyId An opaque string that the server can use to look up the component they need to validate the signature.
     * @param signingAlgorithm An identifier for the HTTP Signature algorithm.
     *  This should be "hs2019" except for legacy applications that use an older version of the draft HTTP signature specification.
     * @param algorithm The detailed algorithm used to sign the message.
     * @param parameterSpec optional cryptographic parameters for the signature.
     * @param headers The list of HTTP headers that will be used in the signature.
     */
    public Signature(final String keyId, final String signingAlgorithm, final String algorithm, final AlgorithmParameterSpec parameterSpec, final List<String> headers) {
        this(keyId, getSigningAlgorithm(signingAlgorithm), getAlgorithm(algorithm), parameterSpec, null, headers);
    }

    private static Algorithm getAlgorithm(final String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("Algorithm cannot be null");
        return Algorithm.get(algorithm);
    }

    private static SigningAlgorithm getSigningAlgorithm(final String scheme) {
        if (scheme == null) throw new IllegalArgumentException("Signing scheme cannot be null");
        return SigningAlgorithm.get(scheme);
    }

    @Deprecated
    public Signature(final String keyId, final String algorithm, final String signature, final String... headers) {
        this(keyId, getAlgorithm(algorithm), signature, headers);
    }

    @Deprecated
    public Signature(final String keyId, final Algorithm algorithm, final String signature, final String... headers) {
        this(keyId, algorithm, signature, Arrays.asList(headers));
    }

    @Deprecated
    public Signature(final String keyId, final String algorithm, final String signature, final List<String> headers) {
        this(keyId, getAlgorithm(algorithm), signature, headers);
    }

    @Deprecated
    public Signature(final String keyId, final Algorithm algorithm, final String signature, final List<String> headers) {
        this(keyId, null, algorithm, null, signature, headers, null, null, null);
    }

    public Signature(final String keyId, final String signingAlgorithm, final String algorithm,
                     final AlgorithmParameterSpec parameterSpec, final String signature, final List<String> headers) {
        this(keyId, getSigningAlgorithm(signingAlgorithm), getAlgorithm(algorithm), parameterSpec, signature, headers);
    }

    public Signature(final String keyId, final SigningAlgorithm signingAlgorithm, final Algorithm algorithm,
                     final AlgorithmParameterSpec parameterSpec, final String signature, final List<String> headers) {
        this(keyId, signingAlgorithm, algorithm, parameterSpec, signature, headers, null);
    }

    public Signature(final String keyId, final SigningAlgorithm signingAlgorithm, final Algorithm algorithm,
                     final AlgorithmParameterSpec parameterSpec, final String signature,
                     final List<String> headers, final Long maxSignatureValidityDuration) {
        this(keyId, signingAlgorithm, algorithm, parameterSpec, signature, headers, maxSignatureValidityDuration, null, null);
    }

    public Signature(final String keyId, final SigningAlgorithm signingAlgorithm, final Algorithm algorithm,
                     final AlgorithmParameterSpec parameterSpec, final String signature,
                     final List<String> headers, final Long maxSignatureValidityDuration,
                     final Long signatureCreatedTime, final Long signatureExpiresTime) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId is required.");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm is required.");
        }
        if (signingAlgorithm != null &&
                signingAlgorithm.getSupportedAlgorithms() != null &&
                !signingAlgorithm.getSupportedAlgorithms().contains(algorithm)) {
            throw new IllegalArgumentException("Signing algorithm " + signingAlgorithm.getAlgorithmName() +
                    " is not compatible with " + algorithm.getPortableName());
        }

        this.keyId = keyId;
        this.signingAlgorithm = signingAlgorithm;
        this.algorithm = algorithm;
        if (maxSignatureValidityDuration != null && maxSignatureValidityDuration <= 0) {
            throw new IllegalArgumentException("Signature max validity must be a positive number");
        }
        this.maxSignatureValidityDuration = maxSignatureValidityDuration;
        this.signatureCreatedTime = signatureCreatedTime;
        this.signatureExpiresTime = signatureExpiresTime;

        // this is the only one that can be null cause the object
        // can be used as a template/specification
        this.signature = signature;

        this.parameterSpec = parameterSpec;

        if (headers == null || headers.size() == 0) {
            final List<String> list = Arrays.asList("date");
            this.headers = Collections.unmodifiableList(list);
        } else {
            this.headers = Collections.unmodifiableList(lowercase(headers));
        }
    }

    /**
     * Returns the signature creation time.
     *
     * @return the signature creation time.
     */
    public Date getSignatureCreation() {
        if (signatureCreatedTime == null) return null;
        return new Date(signatureCreatedTime);
    }

    /**
     * Returns the signature creation time in milliseconds since the epoch.
     *
     * @return the signature creation time in milliseconds since the epoch.
     */
    public Long getSignatureCreationTimeMilliseconds() {
        return signatureCreatedTime;
    }

    /**
     * Returns the signature max validity duration, in milliseconds.
     *
     * @return the signature max validity duration, in milliseconds.
     */
    public Long getSignatureMaxValidityMilliseconds() {
        return maxSignatureValidityDuration;
    }

    /**
     * Returns the signature expiration time.
     *
     * @return the signature expiration time.
     */
    public Date getSignatureExpiration() {
        if (signatureExpiresTime == null) return null;
        return new Date(signatureExpiresTime);
    }

    /**
     * Returns the signature expiration time in milliseconds since the epoch.
     *
     * @return the signature expiration time in milliseconds since the epoch.
     */
    public Long getSignatureExpirationTimeMilliseconds() {
        return signatureExpiresTime;
    }

    private List<String> lowercase(final List<String> headers) {
        final List<String> list = new ArrayList<String>(headers.size());
        for (final String header : headers) {
            list.add(header.toLowerCase());
        }
        return list;
    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * Returns the detailed implementation algorithm for HTTP signatures.
     *
     * @return the cryptographic algorithm.
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the identifier for the HTTP Signature Algorithm, as registered
     * in the HTTP Signature Algorithms Registry.
     *
     * @return the identifier for the HTTP Signature Algorithm.
     */
    public SigningAlgorithm getSigningAlgorithm() {
        return signingAlgorithm;
    }

    /**
     * Returns the base-64 encoded value of the signature.
     *
     * @return the base-64 encoded value of the signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Returns the specification of cryptographic parameters.
     *
     * @return specification of cryptographic parameters.
     */
    public AlgorithmParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    public List<String> getHeaders() {
        return headers;
    }

    /**
     * Verify the signature is valid with regards to the (created) and (expires) fields.
     *
     * When the '(created)' field is present in the HTTP signature, the '(created)' field
     * represents the date when the signature has been created.
     * When the '(expires)' field is present in the HTTP signature, the '(expires)' field
     * represents the date when the signature expires.
     */
    public void verifySignatureValidityDates() {
        if (signatureCreatedTime != null && signatureCreatedTime > System.currentTimeMillis() + maxTimeSkewInMilliseconds) {
            throw new InvalidCreatedFieldException("Signature is not valid yet");
        }
        if (signatureExpiresTime != null && signatureExpiresTime < System.currentTimeMillis()) {
            throw new InvalidExpiresFieldException("Signature has expired");
        }
    }

    /**
     * Constructs a Signature object by parsing the 'Authorization' header.
     *
     * As stated in the HTTP signature specification, the value of the algorithm parameter in
     * the 'Authorization' header should be set to generic identifier. The detailed algorithm
     * should be derived from the keyId. Hence it is not possible to determine the detailed
     * algorithm by inspecting the signature data.
     *
     * @param authorization The value of the HTTP 'Authorization' header containing the signature data.
     * @param algorithm The detailed cryptographic algorithm for the HTTP signature.
     *
     * @return The Signature object.
     */
    public static Signature fromString(String authorization, final Algorithm algorithm) {
        /**
         * A HTTP signature field value in the authorization header.
         */
        class FieldValue {
            /**
             * The field value. It may be a string or number.
             */
            private Object value;
            /**
             * A flag indicating whether the field is a string or number.
             */
            private boolean isNumber;

            FieldValue(final String value, final boolean isNumber) throws ParseException {
                this.isNumber = isNumber;
                if (isNumber) {
                    this.value = NumberFormat.getInstance().parse(value);
                } else {
                    this.value = value;
                }
            }

            /** Returns true if the field is a string */
            boolean isString() {
                return !isNumber;
            }

            /** Returns true if the field is a number */
            boolean isNumber() {
                return isNumber;
            }

            /** Returns true if the field is an integer value */
            boolean isInteger() {
                return value instanceof Long;
            }

            /** Returns the field as a string, or null if the field is not a string. */
            String getValueAsString() {
                if (!isString()) return null;
                return (String) value;
            }

            /** Returns the field as a long value, or null if the field is not a integer number. */
            Long getValueAsLong() {
                if (!isInteger()) return null;
                return ((Number) value).longValue();
            }

            /** Returns the field as a double value, or null if the field is not a number. */
            Double getValueAsDouble() {
                if (!isNumber()) return null;
                return ((Number) value).doubleValue();
            }

        }

        try {
            authorization = normalize(authorization);

            final Map<String, FieldValue> map = new HashMap<String, FieldValue>();

            final Matcher matcher = RFC_2617_PARAM.matcher(authorization);
            while (matcher.find()) {
                final String key = matcher.group("key").toLowerCase();
                // The field value may be a double-quoted string or a number.
                boolean isNumber = false;
                String value = matcher.group("stringValue");
                if (value == null) {
                    value = matcher.group("numberValue");
                    isNumber = true;
                }
                map.put(key, new FieldValue(value, isNumber));
            }

            final List<String> headers = new ArrayList<String>();
            FieldValue fieldValue = map.get("headers");
            if (fieldValue != null) {
                if (!fieldValue.isString()) {
                    throw new IllegalArgumentException("headers field must be a double-quoted string");
                }
                Collections.addAll(headers, fieldValue.getValueAsString().toLowerCase().split(" +"));
            }

            String keyid = null;
            fieldValue = map.get("keyid");
            if (fieldValue != null && fieldValue.isString()) {
                keyid = fieldValue.getValueAsString();
            }
            if (keyid == null) throw new MissingKeyIdException();

            String algorithmField = null;
            fieldValue = map.get("algorithm");
            if (fieldValue != null && fieldValue.isString()) {
                algorithmField = fieldValue.getValueAsString();
            }
            if (algorithmField == null) throw new MissingAlgorithmException();

            String signature = null;
            fieldValue = map.get("signature");
            if (fieldValue != null && fieldValue.isString()) {
                signature = fieldValue.getValueAsString();
            }
            if (signature == null) throw new MissingSignatureException();

            Long created = null; // The signature creation time, in milliseconds since the epoch.
            fieldValue = map.get("created");
            if (fieldValue != null) {
                if (!fieldValue.isInteger()) {
                    throw new InvalidCreatedFieldException("Field must be an integer value");
                }
                created = fieldValue.getValueAsLong() * 1000L;
            }
            Long expires = null; // The signature expiration time, in milliseconds since the epoch.
            fieldValue = map.get("expires");
            if (fieldValue != null) {
                if (!fieldValue.isNumber()) {
                    throw new InvalidExpiresFieldException("Field must be a number");
                }
                expires = (long) (fieldValue.getValueAsDouble() * 1000L);
            }
            SigningAlgorithm parsedSigningAlgorithm = null;
            try {
                parsedSigningAlgorithm = SigningAlgorithm.get(algorithmField);
            } catch (final UnsupportedAlgorithmException ex) {
                // This may happen for older implementations that pass the serialize the detailed
                // algorithm instead of using 'hs2019'. In that case, the value of 'algorithm'
                // should be one of the supported values in the Algorithm enum. If not, an
                // exception is raised.
            }
            Algorithm parsedAlgorithm = null;
            try {
                parsedAlgorithm = Algorithm.get(algorithmField);
                if (algorithm != null && parsedAlgorithm.getPortableName() != algorithm.getPortableName()) {
                    throw new IllegalArgumentException("The algorithm does not match the value of the 'Authorization' header.");
                }
            } catch (final UnsupportedAlgorithmException ex) {
                // This is expected for new conformant implementations that set the algorithm
                // field in the 'Authorization' header to 'hs2019'. The algorithm must be
                // derived from the keyId. The client is responsible for maintaining the
                // mapping between the keyId and the detailed cryptographic algorithm.
                if (algorithm == null) {
                    throw new IllegalArgumentException("The algorithm is required.");
                }
                parsedAlgorithm = algorithm;
            }

            final Signature s = new Signature(keyid, parsedSigningAlgorithm, parsedAlgorithm, null, signature, headers, null, created, expires);
            s.verifySignatureValidityDates();
            return s;

        } catch (final AuthenticationException e) {
            throw e;
        } catch (final Throwable e) {
            throw new UnparsableSignatureException(authorization, e);
        }
    }

    public static Signature fromString(String authorization) {
        return fromString(authorization, null);
    }


    private static String normalize(String authorization) {
        final String start = "signature ";

        final String prefix = authorization.substring(0, start.length()).toLowerCase();

        if (prefix.equals(start)) {
            authorization = authorization.substring(start.length());
        }
        return authorization.trim();
    }

    @Override
    public String toString() {
        return toString("Signature");
    }

    /**
     * Returns the formatted signature parameters without any "Signature " prefix
     */
    public String toParamString() {
        return toString(null);
    }
    
    public String toString(final String prefix) {
        final Object alg;
        if (SigningAlgorithm.HS2019.equals(signingAlgorithm)) {
            // When the signing algorithm is set to 'hs2019', the value of the algorithm
            // field must be set to 'hs2019'. The specific crypto algorithm is not
            // serialized in the 'Authorization' header, the server must derive the value
            // from the keyId.
            alg = signingAlgorithm;
        } else {
            alg = algorithm;
        }
        return  (prefix != null ? prefix + " " : "") +
                "keyId=\"" + keyId + '\"' +
                (signatureCreatedTime != null && headers.contains("(created)") ? String.format(",created=%d", signatureCreatedTime / 1000L) : "") +
                (signatureExpiresTime != null && headers.contains("(expires)") ? String.format(",expires=%.3f", signatureExpiresTime / 1000.0) : "") +
                ",algorithm=\"" + alg + '\"' +
                ",headers=\"" + Join.join(" ", headers) + '\"' +
                ",signature=\"" + signature + '\"';
    }
}
