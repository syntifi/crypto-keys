package com.syntifi.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;

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
public abstract class AbstractPrivateKey implements PrivateKey {
    private byte[] key;

    @Override
    public byte[] getEncoded() {
        return key;
    }

    /**
     * Loads a private key from a byte array
     *
     * @param privateKey the private key bytes
     */
    public abstract void loadPrivateKey(byte[] privateKey) throws IOException;

    /**
     * Reads the private key from a file
     *
     * @param filename the source filename
     * @throws IOException thrown if an error occurs reading the file
     */
    public abstract void readPrivateKey(String filename) throws IOException;


    /**
     * Writes the private key to a file
     *
     * @param filename the target filename
     * @throws IOException thrown if an error occurs writing the file
     */
    public abstract void writePrivateKey(String filename) throws IOException;

    /**
     * Signs a message with the loaded key
     *
     * @param message message to sign
     * @return signed message
     * @throws GeneralSecurityException thrown if an error occurs processing message or signature
     */
    public abstract byte[] sign(byte[] message) throws GeneralSecurityException;

    /**
     * Derives the public key from the loaded private key
     *
     * @return the derived {@link AbstractPublicKey}
     */
    public abstract AbstractPublicKey derivePublicKey();


}
