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

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PemFileHelper {
    public static byte[] readPemFile(String filename) throws IOException {
        try (FileReader keyReader = new FileReader(filename); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            return pemObject.getContent();
        }
    }

    public static void writePemFile(Writer fileWriter, byte[] encodedKey, String keyType) throws IOException {
        try (PemWriter pemWriter = new PemWriter(fileWriter)) {
            pemWriter.writeObject(new PemObject(keyType, encodedKey));
        }
    }

    public static void writePemFile(String filename, byte[] encodedKey, String keyType) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename)) {
            writePemFile(fileWriter, encodedKey, keyType);
        }
    }
}
