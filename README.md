# http-signatures-java

Java Client Library for HTTP Signatures.


## Maven Dependency

Add the following dependency to your Maven pom file.

```
<dependency>
  <groupId>org.tomitribe</groupId>
  <artifactId>tomitribe-http-signatures</artifactId>
  <version>1.0</version>
</dependency>
```

## Bootstrap

Create a template to which all Signatures will be patterned.  To sign messages using the `date` header only, the following template will work:

```
final Signature signature = new Signature("your-key-name", "hmac-sha256", null, "date");
```

To sign messages with a much fuller set of headers, including the Request URI and HTTP Method, use something like the following:

```
final Signature signature = new Signature("your-key-name", "hmac-sha256", null, "content-length", "host", "date", "(request-target)");
```

Then create a `java.security.Key` passing in the shared secret:

```
final Key key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
```

Now finally you tie both together into a `Signer`, which is a thread-safe combination of the two and capable of signing many messages in parallel.

```
final Signer signer = new Signer(key, signature);
```

## Signing

Once you have a `Signer`, signing an HTTP Message is as simple as passing in the respective parts and letting the signer do the magic.

```
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
```

The returned `Signature` object represents a full HTTP Signature.  Simply call `toString()` on it to get a fully formatted `Authorization` header value.

Calling `toString()` on the above `Signature` instance will yeild the following:

```
Signature keyId="my-key-name","algorithm="hmac-sha256",headers="content-length host date (request-target)",signature="yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg="
```
