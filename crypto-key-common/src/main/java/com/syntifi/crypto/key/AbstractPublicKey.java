package com.syntifi.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Abstract class for needed shared functionalities
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public abstract class AbstractPublicKey implements PublicKey {
    private byte[] key;

    @Override
    public byte[] getEncoded() {
        return key;
    }

    /**
     * Loads a public key from a byte array
     *
     * @param publicKey the public key bytes
     */
    public abstract void loadPublicKey(byte[] publicKey) throws IOException;

    /**
     * Reads the public key from a file
     *
     * @param filename the source filename
     * @throws IOException thrown if an error occurs reading the file
     */
    public abstract void readPublicKey(String filename) throws IOException;

    /**
     * Writes the public key to a file
     *
     * @param filename the target filename
     * @throws IOException thrown if an error occurs writing the file
     */
    public abstract void writePublicKey(String filename) throws IOException;

    /**
     * Verifies message with given signature
     *
     * @param message   the signed message
     * @param signature the signature to check against
     * @return true if matches, false otherwise
     * @throws GeneralSecurityException thrown if an error occurs processing message and signature
     */
    public abstract Boolean verify(byte[] message, byte[] signature) throws GeneralSecurityException;
}
