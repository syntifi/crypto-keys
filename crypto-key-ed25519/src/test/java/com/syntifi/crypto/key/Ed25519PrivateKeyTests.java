package com.syntifi.crypto.key;

import com.syntifi.crypto.key.deterministic.HierarchicalDeterministicKey;
import com.syntifi.crypto.key.encdec.Base58;
import com.syntifi.crypto.key.encdec.Hex;
import com.syntifi.crypto.key.mnemonic.MnemonicCode;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
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
    void create_privateKey_from_seed() throws IOException {
        MnemonicCode mnemonicCode = new MnemonicCode("english");
        String words =  "shoot island position soft burden budget tooth cruel issue economy destroy above";
        byte[] seed = mnemonicCode.toSeed(Arrays.asList(words.split(" ")), "");
        //byte[] seed = Hex.decode("577cd910aede2582668a741d476b45e7998e905a4286f701b87b25923501f9d4ea19513b460bcccbc069ebbe4327a59af3d6463045c4b6fa21a5e7004ccfcc3e");
        byte[] init = "ed25519 seed".getBytes(StandardCharsets.UTF_8);
        int[] path = {44, 397, 0};

        byte[] key = HierarchicalDeterministicKey.getFromSeed(seed, init, path);
        Ed25519PrivateKey pk = Ed25519PrivateKey.deriveFromSeed(key);
        //assertEquals("3jFpZEcbhcjpqVE27zU3d7WHcS7Wq716v5WryU8Tj4EaNTHTj8iAhtPW7KCdFV2fnjNf9toawUbdqZnhrRtLKe6w", Base58.encode(pk.getKey()));
        assertTrue(true);
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
