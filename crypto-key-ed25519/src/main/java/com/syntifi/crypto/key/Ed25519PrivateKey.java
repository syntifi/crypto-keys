package com.syntifi.crypto.key;

import com.syntifi.crypto.key.deterministic.HierarchicalDeterministicKey;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * ed25519 implementation of {@link AbstractPrivateKey}
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Ed25519PrivateKey extends AbstractPrivateKey {

    private Ed25519PrivateKeyParameters privateKeyParameters;

    public Ed25519PrivateKey(byte[] privateKey) {
        super(privateKey);
        loadPrivateKey(privateKey);
    }

    @Override
    public void loadPrivateKey(byte[] privateKey) {
        privateKeyParameters = new Ed25519PrivateKeyParameters(privateKey, 0);
    }

    /*
     * SEQUENCE (3 elem) INTEGER 0 SEQUENCE (1 elem) OBJECT IDENTIFIER 1.3.101.112
     * curveEd25519 (EdDSA 25519 signature algorithm) OCTET STRING (32 byte)
     * 38AECE974291F14B5FEF97E1B21F684394120B6E7A8AFB04398BBE787E8BC559 OCTET STRING
     * (32 byte) 38AECE974291F14B5FEF97E1B21F684394120B6E7A8AFB04398BBE787E8BC559
     */
    @Override
    public void readPrivateKey(String filename) throws IOException {
        ASN1Primitive key = ASN1Primitive.fromByteArray(PemFileHelper.readPemFile(filename));
        PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(key);
        String algoId = keyInfo.getPrivateKeyAlgorithm().getAlgorithm().toString();
        if (algoId.equals(Ed25519KeySpec.ED_25519_OID.getId())) {
            privateKeyParameters = new Ed25519PrivateKeyParameters(keyInfo.getPrivateKey().getEncoded(), 4);
            setKey(privateKeyParameters.getEncoded());
        }
    }

    @Override
    public void writePrivateKey(String filename) throws IOException {
        DERSequence derPrefix = new DERSequence(Ed25519KeySpec.ED_25519_OID);
        DEROctetString key = new DEROctetString(new DEROctetString(getKey()));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(0));
        vector.add(derPrefix);
        vector.add(key);
        DERSequence derKey = new DERSequence(vector);
        PemFileHelper.writePemFile(filename, derKey.getEncoded(), Ed25519KeySpec.PRIVATE_KEY_DER_HEADER);
    }

    @Override
    public byte[] sign(byte[] message) {
        Signer signer = new Ed25519Signer();
        signer.init(true, privateKeyParameters);
        signer.update(message, 0, message.length);
        byte[] signature;
        try {
            signature = signer.generateSignature();
            return signature;
        } catch (DataLengthException | CryptoException e) {
            // TODO: throw new SomeException();
            return null;
        }
    }

    @Override
    public AbstractPublicKey derivePublicKey() {
        return new Ed25519PublicKey(privateKeyParameters.generatePublicKey().getEncoded());
    }

    public static Ed25519PrivateKey deriveFromSeed(byte[] seed, int[] path) throws IOException {
        byte[] init = "ed25519 seed".getBytes(StandardCharsets.UTF_8);
        byte[] key = HierarchicalDeterministicKey.getFromSeed(seed, init, path);
        return new Ed25519PrivateKey(key);
    }

    public static Ed25519PrivateKey deriveRandomKey() {
        SecureRandom rnd = new SecureRandom();
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(rnd));
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        Ed25519PrivateKeyParameters privateKeyParameters = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        return new Ed25519PrivateKey(privateKeyParameters.getEncoded());
    }


    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }
}
