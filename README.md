[![Java CI](https://github.com/syntifi/crypto-keys/actions/workflows/build.yml/badge.svg)](https://github.com/syntifi/crypto-keys/actions/workflows/build.yml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/syntifi/crypto-keys?sort=semver)
[![Project license](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0.txt)

# Crypto Keys Java Library

This project wraps public and private keys for common cryptographic functionalities for the following elliptic curves:
  - [Ed25519](https://en.wikipedia.org/wiki/EdDSA)
  - [Secp256k1](https://www.secg.org/sec2-v2.pdf)

## Dependencies

- Java 8
- Maven

## Build instructions

```
./mvnw package
```

## Maven repository

Using gradle

```gradle
// for using ed25519 key pair
implementation com.syntifi.crypto:crypto-key-ed25519:VERSION

// for using secp256k1 key pair
implementation com.syntifi.crypto:crypto-key-secp256k1:VERSION
```

Using maven

```xml

<dependencies>
    ...
    <!-- for using ed25519 key pair -->
    <dependency>
        <groupId>com.syntifi.crypto</groupId>
        <artifactId>crypto-key-ed25519</artifactId>
        <version>VERSION</version>
    </dependency>

    <!-- for using secp256k1 key pair -->
    <dependency>
        <groupId>com.syntifi.crypto</groupId>
        <artifactId>crypto-key-secp256k1</artifactId>
        <version>VERSION</version>
    </dependency>
</dependencies>
```

## How to

### 1. [Read a public key from pem file](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PublicKeyTests.java#L74-L81)

```Java
Ed25519PublicKey publicKey = new Ed25519PublicKey();
publicKey.readPublicKey("public_key.pem");
```

```Java
Secp256k1PublicKey pubKey = new Secp256k1PublicKey();
publicKey.readPublicKey("public_key.pem");
```

### 2. [Write a public key to pem file](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PublicKeyTests.java#L50)

```Java
publicKey.writePublicKey("public_key.pem");
```

### 3. [Read a private key from pem file](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PrivateKeyTests.java#L76-L83)

```Java
Ed25519PrivateKey privateKey = new Ed25519PrivateKey();
privateKey.readPrivateKey("private_key.pem");
```

```Java
Secp256k1PrivateKey privateKey = new Secp256k1PrivateKey();
privateKey.readPrivateKey("private_key.pem");
```

### 4. [Write a private key to pem file](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PrivateKeyTests.java#L57)

```Java
privateKey.writPrivateKey("private_key.pem");
```

### 5. [Sign message](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PrivateKeyTests.java#L65-L67)

```Java
byte[] signature = privateKey.sign("Message".getBytes());
```

### 6. [Verify Signature](https://github.com/syntifi/crypto-keys/blob/d0de1acedd8bfb2d4e7d1074649051af7596f695/crypto-key-ed25519/src/test/java/com/syntifi/crypto/key/Ed25519PublicKeyTests.java#L58-L71)

```Java
 Boolean verified = publicKey.verify(message.getBytes(), Hex.decode(hexSignature));
 ```
