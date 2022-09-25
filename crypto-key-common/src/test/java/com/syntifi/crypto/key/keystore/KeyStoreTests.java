package com.syntifi.crypto.key.keystore;

import com.syntifi.crypto.key.AbstractCryptoTests;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.KeySpec;

public class KeyStoreTests extends AbstractCryptoTests {
    static final char[] PASSWORD = "password".toCharArray();

    @Test
    void create_keystore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore.store(Files.newOutputStream(keyStoreFilePath), PASSWORD);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        Key key = keyGen.generateKey();

        keyStore.setKeyEntry("testKey", key, PASSWORD, null);
        keyStore.store(Files.newOutputStream(keyStoreFilePath), PASSWORD);

        KeySpec keySpec;
    }
}
