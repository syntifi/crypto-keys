package com.syntifi.crypto.key;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.spec.KeySpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Secp256k1KeySpec implements KeySpec {
        public static final String PUBLIC_KEY_DER_HEADER = "PUBLIC KEY";
        public static final String PRIVATE_KEY_DER_HEADER = "PRIVATE KEY";

        public static final ASN1ObjectIdentifier SECP_256_K_1_OID_CURVE = new ASN1ObjectIdentifier("1.3.132.0.10");
        public static final ASN1ObjectIdentifier SECP_256_K_1_OI_DKEY = new ASN1ObjectIdentifier("1.2.840.10045.2.1");
}
