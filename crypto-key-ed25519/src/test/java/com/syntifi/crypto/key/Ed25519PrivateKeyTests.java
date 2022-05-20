package com.syntifi.crypto.key;

import com.syntifi.crypto.key.encdec.Base58;
import com.syntifi.crypto.key.encdec.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link Ed25519PrivateKey}
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.1.0
 */
public class Ed25519PrivateKeyTests extends AbstractCryptoTests {
    private static final Logger LOGGER = LoggerFactory.getLogger(Ed25519PrivateKeyTests.class);

    @Test
    void readPrivateKey_should_load_private_key() throws IOException, URISyntaxException {
        Ed25519PrivateKey privateKey = readPrivateKey("ed25519/secret_key.pem");
        assertNotNull(privateKey.getKey());
    }

    @Test
    void readPrivateKey_derived_public_key_should_equal_generated() throws IOException, URISyntaxException {
        Ed25519PrivateKey privateKey = readPrivateKey("ed25519/secret_key.pem");

        // Compare derived public key to generated hex without leading id byte
        Path hexKeyFilePath = Paths.get(getResourcesKeyPath("ed25519/public_key_hex"));
        String hexKey = new String(Files.readAllBytes(hexKeyFilePath));
        LOGGER.debug("Derived public hex Key from {}: {}", hexKeyFilePath,
                Hex.encode(privateKey.derivePublicKey().getKey()));

        assertEquals(hexKey.substring(2), Hex.encode(privateKey.derivePublicKey().getKey()));
    }

    @Test
    void writePrivateKey_should_equal_source_file() throws URISyntaxException, IOException {
        Ed25519PrivateKey privateKey = readPrivateKey("ed25519/secret_key.pem");

        DateFormat df = new SimpleDateFormat("yyyyMMdd-HHmmss");
        File privateKeyFile = File.createTempFile(df.format(new Date()), "-private-key-test.pem");

        LOGGER.debug("Writing private key to {}", privateKeyFile.getPath());
        privateKey.writePrivateKey(privateKeyFile.getPath());

        assertTrue(compareTextFiles(new File(getResourcesKeyPath("ed25519/secret_key.pem")),
                privateKeyFile));
    }

    @Test
    void sign_should_sign_message() throws URISyntaxException, IOException {
        Ed25519PrivateKey privateKey = readPrivateKey("ed25519/secret_key.pem");

        byte[] signature = privateKey.sign("Test message".getBytes());

        assertEquals(
                "4555103678684364a98478112ce0c298ed841d806d2b67b09e8f0215cc738f3c5a1fca5beaf0474ff636613821bcb97e88b3b4d700e65c6cf7574489e09f170c",
                Hex.encode(signature));

        LOGGER.debug("Signed as {}", signature);
    }

    @Test
    void derived_public_key_should_match_generated() {
        String base58GeneratedPrivateKey = "32UfEkBGTFpfu6M7RebN1JqMDrdf1YyztgYmcUG5XcRkEraJioFZLPtBvYVmAVvnjWAToSsWScJYSFViv8MaATRF";
        String base58GeneratedPublicKey = "F8jARHGZdHqnwrxrnv1pFVzzirXZR2vJzeYbvwQbxZyP";

        Ed25519PrivateKey pk = new Ed25519PrivateKey(Base58.decode(base58GeneratedPrivateKey));

        assertEquals(base58GeneratedPublicKey, Base58.encode(pk.derivePublicKey().getKey()));
    }

    private Ed25519PrivateKey readPrivateKey(String privateKeyPath) throws URISyntaxException, IOException {
        Ed25519PrivateKey privateKey = new Ed25519PrivateKey();
        String keyFilePath = getResourcesKeyPath(privateKeyPath);
        LOGGER.debug("Reading key from {}", keyFilePath);
        privateKey.readPrivateKey(keyFilePath);
        LOGGER.debug("Key: {}", Hex.encode(privateKey.getKey()));
        return privateKey;
    }
}
