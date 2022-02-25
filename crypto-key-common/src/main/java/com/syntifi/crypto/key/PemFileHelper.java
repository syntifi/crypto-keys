package com.syntifi.crypto.key;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;

/**
 * Helper methods for dealing with PEM files
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PemFileHelper {
    /**
     * Reads a PEM file
     *
     * @param filename the filename to read
     * @return a byte array with file content
     * @throws IOException thrown if error reading file
     */
    public static byte[] readPemFile(String filename) throws IOException {
        try (FileReader keyReader = new FileReader(filename); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            return pemObject.getContent();
        }
    }

    /**
     * Writes a PEM file
     *
     * @param fileWriter a filewriter
     * @param encodedKey the encoded key
     * @param keyType    the key type
     * @throws IOException thrown if error writing file
     */
    public static void writePemFile(Writer fileWriter, byte[] encodedKey, String keyType) throws IOException {
        try (PemWriter pemWriter = new PemWriter(fileWriter)) {
            pemWriter.writeObject(new PemObject(keyType, encodedKey));
        }
    }

    /**
     * Writes a PEM file
     *
     * @param filename   the filename to read
     * @param encodedKey the encoded key
     * @param keyType    the key type
     * @throws IOException thrown if error writing file
     */
    public static void writePemFile(String filename, byte[] encodedKey, String keyType) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename)) {
            writePemFile(fileWriter, encodedKey, keyType);
        }
    }
}
