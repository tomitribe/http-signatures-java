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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.spec.AlgorithmParameterSpec;

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
     * OPTIONAL. The duration of the signature validity. If set, this is
     * used to calculate the '(expires)' field in the HTTP signature.
     */
    private Double signatureValidity;

    private static final Pattern RFC_2617_PARAM = Pattern.compile("(\\w+)=\"([^\"]*)\"");

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

    private static Algorithm getAlgorithm(String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("Algorithm cannot be null");
        return Algorithm.get(algorithm);
    }

    private static SigningAlgorithm getSigningAlgorithm(String scheme) {
        if (scheme == null) throw new IllegalArgumentException("Signing scheme cannot be null");
        return SigningAlgorithm.get(scheme);
    }

    public Signature(final String keyId, final String signingAlgorithm, final String algorithm,
                        final AlgorithmParameterSpec parameterSpec, final String signature, final List<String> headers) {
        this(keyId, getSigningAlgorithm(signingAlgorithm), getAlgorithm(algorithm), parameterSpec, signature, headers);
    }

    public Signature(final String keyId, final SigningAlgorithm signingAlgorithm, final Algorithm algorithm,
                        final AlgorithmParameterSpec parameterSpec, final String signature, final List<String> headers) {
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
     * Sets the signature validity, in seconds.
     */
    public Signature signatureValidity(Double signatureValidity) {
        this.signatureValidity = signatureValidity;
        return this;
    }

    /**
     * Returns the value of the signature validity, in seconds.
     * 
     * @return the value of the signature validity, in seconds.
     */
    public Double getSignatureValidity() {
        return signatureValidity;
    }

    private List<String> lowercase(List<String> headers) {
        final List<String> list = new ArrayList<String>(headers.size());
        for (String header : headers) {
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
    public static Signature fromString(String authorization, Algorithm algorithm) {
        try {
            authorization = normalize(authorization);

            final Map<String, String> map = new HashMap<String, String>();

            final Matcher matcher = RFC_2617_PARAM.matcher(authorization);
            while (matcher.find()) {
                final String key = matcher.group(1).toLowerCase();
                final String value = matcher.group(2);
                map.put(key, value);
            }

            final List<String> headers = new ArrayList<String>();
            final String headerString = map.get("headers");
            if (headerString != null) {
                Collections.addAll(headers, headerString.toLowerCase().split(" +"));
            }

            final String keyid = map.get("keyid");
            if (keyid == null) throw new MissingKeyIdException();

            final String algorithmField = map.get("algorithm");
            if (algorithmField == null) throw new MissingAlgorithmException();

            final String signature = map.get("signature");
            if (signature == null) throw new MissingSignatureException();

            SigningAlgorithm parsedSigningAlgorithm = null;
            try {
                parsedSigningAlgorithm = SigningAlgorithm.get(algorithmField);
            } catch (UnsupportedAlgorithmException ex) {
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
            } catch (UnsupportedAlgorithmException ex) {
                // This is expected for new conformant implementations that set the algorithm
                // field in the 'Authorization' header to 'hs2019'. The algorithm must be
                // derived from the keyId. The client is responsible for maintaining the
                // mapping between the keyId and the detailed cryptographic algorithm.
                if (algorithm == null) {
                    throw new IllegalArgumentException("The algorithm is required.");
                }
                parsedAlgorithm = algorithm;
            }

            return new Signature(keyid, parsedSigningAlgorithm, parsedAlgorithm, null, signature, headers);

        } catch (AuthenticationException e) {
            throw e;
        } catch (Throwable e) {
            throw new UnparsableSignatureException(authorization, e);
        }
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
        return "Signature " +
                "keyId=\"" + keyId + '\"' +
                ",algorithm=\"" + algorithm + '\"' +
                ",headers=\"" + Join.join(" ", headers) + '\"' +
                ",signature=\"" + signature + '\"';
    }
}
