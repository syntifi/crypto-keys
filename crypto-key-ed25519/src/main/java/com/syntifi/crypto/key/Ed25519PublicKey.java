package com.syntifi.crypto.key;

import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * ed25519 implementation of {@link AbstractPublicKey}
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Ed25519PublicKey extends AbstractPublicKey {

    private Ed25519PublicKeyParameters publicKeyParameters;

    public Ed25519PublicKey(byte[] publicKey) {
        super(publicKey);
        loadPublicKey(publicKey);
    }

    @Override
    public void loadPublicKey(byte[] publicKey) {
        publicKeyParameters = new Ed25519PublicKeyParameters(publicKey, 0);
    }

    /*
     * SEQUENCE (2 elem) SEQUENCE (1 elem) OBJECT IDENTIFIER 1.3.101.112
     * curveEd25519 (EdDSA 25519 signature algorithm) BIT STRING (256 bit) <KEY
     * HERE>
     */
    @Override
    public void readPublicKey(String filename) throws IOException {
        ASN1Primitive derKey = ASN1Primitive.fromByteArray(PemFileHelper.readPemFile(filename));
        ASN1Sequence objBaseSeq = ASN1Sequence.getInstance(derKey);
        String objId = ASN1ObjectIdentifier
                .getInstance(ASN1Sequence.getInstance(objBaseSeq.getObjectAt(0)).getObjectAt(0)).getId();
        if (objId.equals(ASN1Identifiers.Ed25519OID.getId())) {
            DERBitString key = DERBitString.getInstance(objBaseSeq.getObjectAt(1));
            publicKeyParameters = new Ed25519PublicKeyParameters(key.getBytes(), 0);
            setKey(publicKeyParameters.getEncoded());
        }
    }

    @Override
    public void writePublicKey(String filename) throws IOException {
        DERSequence derPrefix = new DERSequence(ASN1Identifiers.Ed25519OID);
        DERBitString key = new DERBitString(getKey());
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(derPrefix);
        vector.add(key);
        DERSequence derKey = new DERSequence(vector);
        PemFileHelper.writePemFile(filename, derKey.getEncoded(), ASN1Identifiers.PUBLIC_KEY_DER_HEADER);
    }

    @Override
    public Boolean verify(byte[] message, byte[] signature) {
        Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);
    }
}
