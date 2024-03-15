package com.syntifi.crypto.key;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.*;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * secp256k1 implementation of {@link AbstractPrivateKey}
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Secp256k1PrivateKey extends AbstractPrivateKey {
    @Getter
    @Setter
    private ECKeyPair keyPair;

    public Secp256k1PrivateKey(byte[] privateKey) throws IOException {
        super(privateKey);
        loadPrivateKey(privateKey);
    }

    @Override
    public void loadPrivateKey(byte[] privateKey) throws IOException {
        ASN1Sequence key = (ASN1Sequence) ASN1Primitive.fromByteArray(privateKey);
        String algoId = key.getObjectAt(2).toString();
        if (algoId.equals("[0]" + ASN1Identifiers.Secp256k1OIDCurve) && key.getObjectAt(0).toString().equals("1")) {
            DEROctetString pk = (DEROctetString) key.getObjectAt(1);
            keyPair = ECKeyPair.create(pk.getOctets());
            this.setKey(keyPair.getPrivateKey().toByteArray());
        }
    }

    @Override
    public void readPrivateKey(String filename) throws IOException {
        loadPrivateKey(PemFileHelper.readPemFile(filename));
    }

    @Override
    public void writePrivateKey(String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename)) {
            DERTaggedObject derPrefix = new DERTaggedObject(0, ASN1Identifiers.Secp256k1OIDCurve);
            DEROctetString key = new DEROctetString(getKey());
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(1));
            vector.add(key);
            vector.add(derPrefix);
            DERSequence derKey = new DERSequence(vector);
            PemFileHelper.writePemFile(fileWriter, derKey.getEncoded(), ASN1Identifiers.EC_PRIVATE_KEY_DER_HEADER);
        }
    }

    /*
     * When encoded in DER, this becomes the following sequence of bytes:
     * <p>
     * 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
     * <p>
     * where:
     * <p>
     * b1 is a single byte value, equal to the length, in bytes, of the remaining
     * list of bytes (from the first 0x02 to the end of the encoding);
     * b2 is a single byte value, equal to the length, in bytes, of (vr);
     * b3 is a single byte value, equal to the length, in bytes, of (vs);
     * (vr) is the signed big-endian encoding of the value "r
     * <p>
     * ", of minimal length;
     * (vs) is the signed big-endian encoding of the value "s
     * ", of minimal length.
     */
    @Override
    public byte[] sign(byte[] message) {
        SignatureData signature = Sign.signMessage(Hash.sha256(message), keyPair, false);
        // TODO: Check this conversion
        //return Hex.toHexString(signature.getR()) + Hex.toHexString(signature.getS());
        ByteBuffer bb = ByteBuffer.allocate(signature.getR().length + signature.getS().length);
        bb.put(signature.getR());
        bb.put(signature.getS());
        return bb.array();
    }

    /*
     * Returns a Secp256k1PublicKey object in a compressed format
     * adding the prefix 02/03 to identify the positive or negative Y followed
     * by the X value in the elliptic curve
     */
    @Override
    public AbstractPublicKey derivePublicKey() {
        BigInteger pubKey = keyPair.getPublicKey();
        byte[] pubKeyBytes = Secp256k1PublicKey.getShortKey(pubKey.toByteArray());
        return new Secp256k1PublicKey(pubKeyBytes);
    }

    public static Secp256k1PrivateKey deriveRandomKey() {
        SecureRandom rnd = new SecureRandom();
        ECKeyPair keyPair = ECKeyPair.create(rnd.generateSeed(32));
        Secp256k1PrivateKey sk = new Secp256k1PrivateKey();
        sk.setKeyPair(keyPair);
        sk.setKey(keyPair.getPrivateKey().toByteArray());
        return sk;
    }

}
