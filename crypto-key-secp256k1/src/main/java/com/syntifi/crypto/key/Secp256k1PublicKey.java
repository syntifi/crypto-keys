package com.syntifi.crypto.key;

import com.syntifi.crypto.key.encdec.Hex;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.*;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * secp256k1 implementation of {@link AbstractPublicKey}
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Secp256k1PublicKey extends AbstractPublicKey {

    public Secp256k1PublicKey(byte[] bytes) {
        super(bytes);
    }

    @Override
    public void loadPublicKey(byte[] publicKey) throws IOException {
        ASN1Primitive derKey = ASN1Primitive.fromByteArray(publicKey);
        ASN1Sequence objBaseSeq = ASN1Sequence.getInstance(derKey);
        String keyId = ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(objBaseSeq.getObjectAt(0)).getObjectAt(0)).getId();
        String curveId = ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(objBaseSeq.getObjectAt(0)).getObjectAt(1)).getId();
        if (curveId.equals(Secp256k1KeySpec.SECP_256_K_1_OID_CURVE.getId())
                && keyId.equals(Secp256k1KeySpec.SECP_256_K_1_OI_DKEY.getId())) {
            DERBitString key = DERBitString.getInstance(objBaseSeq.getObjectAt(1));
            setKey(key.getBytes());
        } else {
            throw new IOException();
        }

    }

    @Override
    public void readPublicKey(String filename) throws IOException {
        loadPublicKey(PemFileHelper.readPemFile(filename));
    }

    @Override
    public void writePublicKey(String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename)) {
            DERBitString key = new DERBitString(getKey());
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            v1.add(Secp256k1KeySpec.SECP_256_K_1_OI_DKEY);
            v1.add(Secp256k1KeySpec.SECP_256_K_1_OID_CURVE);
            DERSequence derPrefix = new DERSequence(v1);
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add(derPrefix);
            v2.add(key);
            DERSequence derKey = new DERSequence(v2);
            PemFileHelper.writePemFile(fileWriter, derKey.getEncoded(), Secp256k1KeySpec.PUBLIC_KEY_DER_HEADER);
        }
    }

    @Override
    public Boolean verify(byte[] message, byte[] signature) throws GeneralSecurityException {
        //TODO: Double check the issue the getV(), for now we are trying with both (27 and 28)
        SignatureData signatureData1 = new SignatureData(
                (byte) 27,
                Arrays.copyOfRange(signature, 0, 32),
                Arrays.copyOfRange(signature, 32, 64));
        BigInteger derivedKey1 = Sign.signedMessageHashToKey(Hash.sha256(message), signatureData1);
        SignatureData signatureData2 = new SignatureData(
                (byte) 28,
                Arrays.copyOfRange(signature, 0, 32),
                Arrays.copyOfRange(signature, 32, 64));
        BigInteger derivedKey2 = Sign.signedMessageHashToKey(Hash.sha256(message), signatureData2);
        return Arrays.equals(Secp256k1PublicKey.getShortKey(derivedKey1.toByteArray()), getKey()) ||
                Arrays.equals(Secp256k1PublicKey.getShortKey(derivedKey2.toByteArray()), getKey());
    }

    /**
     * Gets a short key
     *
     * @param key the key as a byte array
     * @return short key as byte array
     */
    public static byte[] getShortKey(byte[] key) {
        BigInteger pubKey = new BigInteger(key);
        String pubKeyPrefix = pubKey.testBit(0) ? "03" : "02";
        byte[] pubKeyBytes = Arrays.copyOfRange(key, 0, 32);
        return Hex.decode(pubKeyPrefix + Hex.encode(pubKeyBytes));
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
