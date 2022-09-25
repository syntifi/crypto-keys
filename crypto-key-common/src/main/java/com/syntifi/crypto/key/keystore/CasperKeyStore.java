package com.syntifi.crypto.key.keystore;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class CasperKeyStore implements AutoCloseable {

    @Getter
    @AllArgsConstructor
    public enum CasperKeyStoreType {
        PKCS12("PKCS12");

        private String typeName;
    }

    static final CasperKeyStoreType DEFAULT_KEYSTORE_TYPE = CasperKeyStoreType.PKCS12;
    static final String DEFAULT_KEYSTORE_FILENAME = "casper_keystore.p12";

    public CasperKeyStore(String password) {
        this(DEFAULT_KEYSTORE_FILENAME, DEFAULT_KEYSTORE_TYPE, password);
    }

    public CasperKeyStore(String filename, CasperKeyStoreType keyStoreType, String password) throws CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(DEFAULT_KEYSTORE_TYPE.getTypeName());
        keyStore.load(null, null);
        Path keyStoreFilePath = Paths.get(filename);

    }

    @Override
    public void close() throws Exception {
        System.out.println("Closed MyResource");
    }
}
