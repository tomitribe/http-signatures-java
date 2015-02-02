package org.tomitribe.auth.signatures;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;

public class AlgorithmsTest extends Assert {

    private static final String[] hmac = {"Hmac", "HMAC", "hmac", "hMaC"};
    private static final String[] rsa = {"Rsa", "RSA", "rsa", "rSA", "rSa"};
    private static final String[] dsa = {"Dsa", "DSA", "dsa", "dSA", "dSa"};
    private static final String[] delimiters = {"", " ", "-"};
    private static final String[] sha = {"sha", "SHA", "sha", "SHA", "sHa"};
    private static final String[] one = {"1", "128"};
    private static final String[] two = {"2", "256"};
    private static final String[] five12 = {"512"};

    @Test
    public void testToPortableName() throws Exception {

        assertPortableName("hmac-sha128", hmac, delimiters, sha, one);
        assertPortableName("hmac-sha256", hmac, delimiters, sha, two);
        assertPortableName("hmac-sha512", hmac, delimiters, sha, five12);

        assertPortableName("rsa-sha128", rsa, delimiters, sha, one);
        assertPortableName("rsa-sha256", rsa, delimiters, sha, two);
        assertPortableName("rsa-sha512", rsa, delimiters, sha, five12);

        assertPortableName("dsa-sha128", dsa, delimiters, sha, one);
        assertPortableName("dsa-sha256", dsa, delimiters, sha, two);
        assertPortableName("dsa-sha512", dsa, delimiters, sha, five12);
    }

    @Test
    public void testToJvmName() throws Exception {

        assertJvmName("HmacSHA128", hmac, delimiters, sha, one);
        assertJvmName("HmacSHA256", hmac, delimiters, sha, two);
        assertJvmName("HmacSHA512", hmac, delimiters, sha, five12);

        assertJvmName("RsaSHA128", rsa, delimiters, sha, one);
        assertJvmName("RsaSHA256", rsa, delimiters, sha, two);
        assertJvmName("RsaSHA512", rsa, delimiters, sha, five12);

        assertJvmName("DsaSHA128", dsa, delimiters, sha, one);
        assertJvmName("DsaSHA256", dsa, delimiters, sha, two);
        assertJvmName("DsaSHA512", dsa, delimiters, sha, five12);
    }

    private void assertPortableName(final String expected, final String[] type, final String[] delimiters, final String[] sha, final String[] bits) {
        for (String text : matrix(type, delimiters, sha, bits)) {
            assertEquals(expected, Algorithms.toPortableName(text));
        }
    }

    private void assertJvmName(final String expected, final String[] type, final String[] delimiters, final String[] sha, final String[] bits) {
        for (String text : matrix(type, delimiters, sha, bits)) {
            assertEquals(expected, Algorithms.toJvmName(text));
        }
    }

    private Iterable<String> matrix(String[] hmac, String[] delimiters, String[] sha, String[] one) {
        // this could be fancier and create the strings as we iterate,
        // but this is good enough
        final List<String> list = new ArrayList<String>();
        for (String h : hmac) {
            for (String d : delimiters) {
                for (String s : sha) {
                    for (String o : one) {
                        list.add(h + d + s + o);
                    }
                }
            }
        }
        return list;
    }
}