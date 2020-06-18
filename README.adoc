= HTTP Signatures Java Client
:showtitle:

HTTP signatures provide a mechanism by which a shared secret key can be used to digitally "sign" a HTTP message to both verify the
identity of the sender and verify that the message has not been tampered with in-transit.

This is done by concatenating the desired HTTP Headers together to form a string called a "Signing String".  An encrypted 
hash (digitial signature) is made of the Signing String using either an asymmetric algorithm (`rsa-sha256`) with a 
public/private key pair or a symmetric algorithm (`hmac-sha256`) with a shared secret key.

Finally, the encrypted bytes are Base64 encoded and added to the `Authorization` header, along with the `keyId`, signing algorithm, header names, and the signature itself.

For example, the following Signing String:

[source]
----
digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
date: Tue, 07 Jun 2014 20:51:35 GMT
(request-target): get /foo/Bar
----

if encrypted using the `hmac-sha256` algorithm with the secret +don't tell+, and then encoded with Base64 would yield the result:

[source]
----
6aq7lLvqJlYRhEBkvl0+qMuSbMyxalPICsBh1qV6V/s=
----

This would then be applied to the Authorization header as below:

[source]
----
Authorization: Signature keyId="myusername:mykey",algorithm="hmac-sha256",headers="digest 
date (request-target)",signature="6aq7lLvqJlYRhEBkvl0+qMuSbMyxalPICsBh1qV6V/s="
----

== Maven Dependency

Add the following dependency to your Maven pom file.

[source,xml]
----
<dependency>
  <groupId>org.tomitribe</groupId>
  <artifactId>tomitribe-http-signatures</artifactId>
  <version>1.5</version>
</dependency>
----

== Library Overview

There are 2 key classes in this library:

* `Signature` - defines the headers that make up the signature - this must as a minimum include the headers that the server requires to be part of the signature
* `Signer` - computes the signature value using the headers/values defined on the +Signature+ classes

=== Creating a Signer

The `Signer` instance is intended to be created once and reused to sign all the HTTP messages that require HTTP Signature Authentication. 

It is immutable, fully thread-safe and optimized to check and verify the supplied Key on construction.

The first steps to creating a Signer instance are as follows:

[source,java]
----
final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)"); // <1>
final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");	 // <2>
final Signer signer = new Signer(key, signature); // <3>
----

<1> Define a new `Signature` object.  This `Signature` object isn't fully computed signature, but rather a template for the Signatures
that will be created by the `Signer` for specific HTTP messages.  It requires a key alias (1st parameter), the signature algorithm (2nd parameter - usually "hmac-sha256") and a var-arg list of header names indicating which headers will require signing (4th - nth parameters).
<2> Define a SecretKeySpec instance, this needs the shared secret passphrase, and the algorithm used to store it in the keystore (usually "HmacSHA256").
<3> Initialize a new Signer object with the key and signature from <1> and <2> above

=== Signing an HTTP Message

Once you have a `Signer`, signing an HTTP Message is as simple as passing in the respective parts and letting the signer do the
magic. The library is not specific to any HTTP Client Java library such as Apache HttpClient, therefore data must be copied from
the request object of your specifc HTTP Client library and passed to the `Signer` in simple `String` and `Map` form.

[source,java]
----
final String method = "GET";

final String uri = "/foo/Bar";

final Map<String, String> headers = new HashMap<String, String>();
headers.put("Host", "example.org");
headers.put("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
headers.put("Content-Type", "application/json");
headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
headers.put("Accept", "*/*");
headers.put("Content-Length", "18");

// Here it is!
final Signature signed = signer.sign(method, uri, headers);
----

The returned `Signature` object represents a full HTTP Signature.  Simply call `toString()` on it to get a fully formatted `Authorization` header value.

Calling `toString()` on the above `Signature` instance will yeild the following:

[source]
----
Signature keyId="my-key-name","algorithm="hmac-sha256",headers="content-length host date (request-target)",signature="yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg="
----

The output of +signature.toString()+ should be used as the value the +Authorization+ header for the request.

== Scenarios

The following sections demonstrate a few common scenarios using http-signatures-java.

=== Simple (request-target)

This is the simplest request. Only the request-target (URI) is used to build the signature.

[source,java]
----
final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)"); // <1>
final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");
final Signer signer = new Signer(key, signature);
final Map<String, String> headers = new HashMap<>();
return signer.sign(method, uri, headers); // <2>
----

<1> Define the +Signature+ object using just the "(request-target)" (note the use of parenthesis) element.
<2> Use the +Signer+ class with the method, URI, and an empty header map to create the signature.

=== (request-target) date (with date validation)

This is similar to the the previous example, but expands on it by adding the date header to the signature. The date should be created in the "EEE, dd MMM yyyy HH:mm:ss zzz" format, and the exact same date should be passed to the +Signer+ as is used on the +Date+ header.

[source,java]
----
final Date today = new Date(); // default window is 1 hour
final String stringToday = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US).format(today);

final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)", "date");  // <1>
final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");
final Signer signer = new Signer(key, signature);
final Map<String, String> headers = new HashMap<>();
s.put("Date", stringToday);	 // <2>
return signer.sign(method, uri, headers);				
----

<1> Define the +Signature+ object with the "(request-target)" and "date" headers
<2> Include the date in the headers map

=== Message body digest

[source,java]
----
final byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload.getBytes()); // <1>
final String digestHeader = "SHA-256=" + new String(Base64.encodeBase64(digest));

final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)", "digest"); // <2>
final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");
final Signer signer = new Signer(key, signature);
final Map<String, String> headers = new HashMap<>();
headers.put("digest", digestHeader);
return signer.sign(method, uri, headers);
----

<1> Define the +Signature+ object with the "(request-target)" and "digest" headers
<2> Include the digest in the headers map

== References

Signing HTTP Messages (Internet Draft) https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00

Instance Digests in HTTP http://tools.ietf.org/html/rfc3230

= Signing Examples

== Java 8

[source,java]
----
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SigningExample {

    public static void main(String... s) throws Exception {

        final String key = "don't tell";

        final String signingString = "digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n" +
                "date: Tue, 07 Jun 2014 20:51:35 GMT\n" +
                "(request-target): get /foo/Bar";

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256"));
        final byte[] signedBytes = mac.doFinal(signingString.getBytes("UTF-8"));
        final Base64.Encoder encoder = Base64.getEncoder();

        final String result = new String(encoder.encode(signedBytes), "UTF-8");

        if (!"6aq7lLvqJlYRhEBkvl0+qMuSbMyxalPICsBh1qV6V/s=".equals(result)) {
            throw new IllegalStateException("Signing failed");
        }

        System.out.println(result);
    }
}
----

== Bash

[source,java]
----
#!/bin/bash

# Secret Key
KEY="don't tell"

# Create the Signing string from the required headers
STRING='digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
date: Tue, 07 Jun 2014 20:51:35 GMT
(request-target): get /foo/Bar'

# Sign the string, base64
echo -n "$STRING" | openssl dgst -binary -sha256 -hmac "$KEY" | base64
----

Running this will print:

----
6aq7lLvqJlYRhEBkvl0+qMuSbMyxalPICsBh1qV6V/s=
----
