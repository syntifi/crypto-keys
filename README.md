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

<dependency>
    <groupId>com.syntifi.crypto</groupId>
    <artifactId>crypto-key-ed2551</artifactId>
    <version>VERSION</version>
</dependency>

<dependency>
    <groupId>com.syntifi.crypto</groupId>
    <artifactId>crypto-key-secp256k1</artifactId>
    <version>VERSION</version>
</dependency>
```