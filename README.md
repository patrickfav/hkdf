# HKDF

[Hashed Message Authentication Code](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) (HMAC)-based key derivation function ([HKDF](https://en.wikipedia.org/wiki/HKDF)), can be used as a building block in various protocols and applications.  The [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) is intended to support a wide range of applications and requirements, and is conservative in its use of [cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function). It is likely to have [better security properties](https://crypto.stackexchange.com/questions/13232/how-is-hkdf-expand-better-than-a-simple-hash) than KDF's based on just a hash functions alone. See [RFC 5869](https://tools.ietf.org/html/rfc5869) for full detail.

[![Download](https://api.bintray.com/packages/patrickfav/maven/hkdf/images/download.svg)](https://bintray.com/patrickfav/maven/hkdf/_latestVersion)
[![Build Status](https://travis-ci.org/patrickfav/hkdf.svg?branch=master)](https://travis-ci.org/patrickfav/hkdf)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/hkdf.svg)](https://www.javadoc.io/doc/at.favre.lib/hkdf)
[![Coverage Status](https://coveralls.io/repos/github/patrickfav/hkdf/badge.svg?branch=master)](https://coveralls.io/github/patrickfav/hkdf?branch=master)

This is supposed to be a standalone, lightweight, simple to use, fully tested and stable implementation in Java. The code is compiled with [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications. It passes all test vectors from [RFC 5869 Appendix A.](https://tools.ietf.org/html/rfc5869#appendix-A)

## Quickstart

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>hkdf</artifactId>
        <version>{latest-version}</version>
    </dependency>

A very simple example:

```java
byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(null, lowEntropyInput);
byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);
```

### Full Example

This example creates high-quality [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) key and initialization vector from a bad
user input and encrypts with [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) block mode:

```java
//if no dynamic salt is available, a static salt is better than null
byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

//example input
String userInput = "this is a user input with bad entropy";

HKDF hkdf = HKDF.fromHmacSha256();

//extract the "raw" data to create output with concentrated entropy
byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, userInput.getBytes(StandardCharsets.UTF_8));

//create expanded bytes for e.g. AES secret key and IV
byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

//Example boilerplate encrypting a simple string with created key/iv
SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(expandedIv));
byte[] encrypted = cipher.doFinal("my secret message".getBytes(StandardCharsets.UTF_8));
```

### Using custom HMAC implementation

```java
//don't use md5, this is just an example
HKDF hkdfMd5 = HKDF.from(new HkdfMacFactory.Default("HmacMD5", 16, Security.getProvider("SunJCE")));

byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};
byte[] outputKeyingMaterial = hkdfMd5.extractAndExpand(null, lowEntropyInput null, 32);
```

## Download

The artifacts are deployed to [jcenter](https://bintray.com/bintray/jcenter) and [Maven Central](https://search.maven.org/).

### Maven

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>hkdf</artifactId>
        <version>{latest-version}</version>
    </dependency>

### Gradle

Add to your `build.gradle` module dependencies:

    compile group: 'at.favre.lib', name: 'hkdf', version: '{latest-version}'

### Local Jar

[Grab jar from latest release.](https://github.com/patrickfav/hkdf/releases/latest)


## Description

For the full description see the [RFC 5869](https://tools.ietf.org/html/rfc5869). For
an in-depth discussion about the security considerations [see the Paper "Cryptographic Extraction and Key Derivation: The HKDF Scheme (2010)" by Hugo Krawczyk](https://eprint.iacr.org/2010/264). The following
is a summary of the 2 sources above. If there seems to be a contradiction, the original
sources are always correct over this.

### Extract and Expand

HKDF follows the "extract-then-expand" paradigm, where the KDF logically consists of two modules.

1. To "extract" (condense/blend) entropy from a larger random source to provide a more uniformly unbiased and higher entropy but smaller output. This is done by utilising the diffusion properties of cryptographic MACs.
2. To "expand" the generated output of an already reasonably random input such as an existing shared key into a larger cryptographically independent output, thereby producing multiple keys deterministically from that initial shared key, so that the same process may produce those same secret keys safely on multiple devices, as long as the same inputs are utilised.

Note that some existing KDF specifications, such as NIST Special Publication 800-56A, NIST Special Publication 800-108 and IEEE Standard 1363a-2004, either only consider the second stage (expanding a pseudorandom key), or do not explicitly differentiate between the "extract" and "expand" stages, often resulting in design shortcomings.  The goal of this HKDF is to accommodate a wide range of KDF requirements while minimizing the assumptions about the underlying hash function.

### Use Cases

HKDF is intended for use in a wide variety of KDF applications. Some applications _will not be able_ to use HKDF "as-is" due to specific operational requirements. One significant example is the derivation of cryptographic keys from a source of low entropy, such as a user's password. In the case of _password-based KDFs_, a main goal is to slow down dictionary attacks. HKDF naturally accommodates the use of salt; _however, a slowing down mechanism is not part of this specification_. Therefore, for a user's password, other KDFs might be considered like: [PKDF2](https://en.wikipedia.org/wiki/PBKDF2), [bcryt](https://en.wikipedia.org/wiki/Bcrypt), [scrypt](https://en.wikipedia.org/wiki/Scrypt) or [Argon2](https://github.com/P-H-C/phc-winner-argon2) which are all designed to be computationally intensive.

#### Key Derivation

The following examples are from [RFC5869 Section 4](https://tools.ietf.org/html/rfc5869#section-4):

* The derivation of cryptographic keys from a shared Diffie-Hellman value in a key-agreement protocol.
* The derivation of symmetric keys from a hybrid public-key encryption scheme.
* Key derivation for key-wrapping mechanisms.

##### Creating multiple keys from a single input

The expand phase includes an "info" parameter which should be used to create
multiple key material from a single PRK source. For example a Secret Key and
IV from a shared Diffie-Hellman Value.

#### Pseudorandom number generator (PRNG)

These two functions may also be combined and used to form a PRNG to improve a random number generator's potentially-biased output, as well as protect it from analysis and help defend the random number generation from malicious inputs.

## Digital Signatures

### Signed Jar

The provided JARs in the Github release page are signed with my private key:

    CN=Patrick Favre-Bulle, OU=Private, O=PF Github Open Source, L=Vienna, ST=Vienna, C=AT
    Validity: Thu Sep 07 16:40:57 SGT 2017 to: Fri Feb 10 16:40:57 SGT 2034
    SHA1: 06:DE:F2:C5:F7:BC:0C:11:ED:35:E2:0F:B1:9F:78:99:0F:BE:43:C4
    SHA256: 2B:65:33:B0:1C:0D:2A:69:4E:2D:53:8F:29:D5:6C:D6:87:AF:06:42:1F:1A:EE:B3:3C:E0:6D:0B:65:A1:AA:88

Use the jarsigner tool (found in your `$JAVA_HOME/bin` folder) folder to verify.

### Signed Commits

All tags and commits by me are signed with git with my private key:

    GPG key ID: 4FDF85343912A3AB
    Fingerprint: 2FB392FB05158589B767960C4FDF85343912A3AB

## Build

### Jar Sign

If you want to jar sign you need to provide a file `keystore.jks` in the
root folder with the correct credentials set in environment variables (
`OPENSOURCE_PROJECTS_KS_PW` and `OPENSOURCE_PROJECTS_KEY_PW`); alias is
set as `pfopensource`.

If you want to skip jar signing just change the skip configuration in the
`pom.xml` jar sign plugin to true:

    <skip>true</skip>

### Build with Maven

Use maven (3.1+) to create a jar including all dependencies

    mvn clean install

## Tech Stack

* Java 7
* Maven

## HKDF Implementations in Java

* [Mozilla: sync-crypto](https://github.com/mozilla-services/sync-crypto/blob/master/src/main/java/org/mozilla/android/sync/crypto/HKDF.java)
* [WhisperSystems: libsignal-protocol-java](https://github.com/WhisperSystems/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/kdf/HKDF.java)
* [Square: keywhiz](https://github.com/square/keywhiz/blob/master/hkdf/src/main/java/keywhiz/hkdf/Hkdf.java)
* [Bouncy Castle](https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/generators/HKDFBytesGenerator.java)

# License

Copyright 2017 Patrick Favre-Bulle

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
