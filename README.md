[![Java CI](https://github.com/syntifi/crypto-keys/actions/workflows/build.yml/badge.svg)](https://github.com/syntifi/crypto-keys/actions/workflows/build.yml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/syntifi/crypto-keys?sort=semver)
[![Project license](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0.txt)

# Syntifi Crypto Keys Java Library

This project wraps public and private keys for common cryptographic functionalities.

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
implementation com.syntifi.crypto:crypto-key-ed2551:VERSION
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