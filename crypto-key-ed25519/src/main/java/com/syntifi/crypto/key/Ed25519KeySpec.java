package com.syntifi.crypto.key;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.spec.KeySpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Ed25519KeySpec implements KeySpec {
    public static final String PUBLIC_KEY_DER_HEADER = "PUBLIC KEY";
    public static final String PRIVATE_KEY_DER_HEADER = "EC PRIVATE KEY";

    public static final ASN1ObjectIdentifier ED_25519_OID = new ASN1ObjectIdentifier("1.3.101.112");
}
