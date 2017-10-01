# HKDF

Hashed Message Authentication Code (HMAC)-based key derivation function (HKDF), can be used as a building block in various protocols and applications.  The key derivation function (KDF) is intended to support a wide range of applications and requirements, and is conservative in its use of cryptographic hash functions.

 [![GitHub release](https://img.shields.io/github/release/patrickfav/hkdf.svg)](https://github.com/patrickfav/hkdf/releases/latest)
[![Build Status](https://travis-ci.org/patrickfav/hkdf.svg?branch=master)](https://travis-ci.org/patrickfav/hkdf)
[![Coverage Status](https://coveralls.io/repos/github/patrickfav/hkdf/badge.svg?branch=master)](https://coveralls.io/github/patrickfav/hkdf?branch=master)

## Quickstart

Add dependency to your pom.xml:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>hkdf</artifactId>
        <version>{latest-version}</version>
    </dependency>

A very simple example:

```java
byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(lowEntropyInput, null);
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
byte[] pseudoRandomKey = hkdf.extract(userInput.getBytes(StandardCharsets.UTF_8), staticSalt32Byte);

//create expanded bytes for e.g. AES secret key and IV
byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

//Example boilerplate encrypting a simple string with created key/iv
SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(expandedIv));
yte[] encrypted = cipher.doFinal("my secret message".getBytes(StandardCharsets.UTF_8));
```

## Download

**[Grab jar from latest Release](https://github.com/patrickfav/hkdf/releases/latest)**


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
