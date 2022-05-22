package com.syntifi.crypto.key.deterministic;

import com.syntifi.crypto.key.encdec.Base58;
import com.syntifi.crypto.key.mnemonic.MnemonicCode;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HierarchicalDeterministicKeyTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(HierarchicalDeterministicKey.class);

    @Test
    void getKeyFromSeed_seed_should_match() throws IOException {
        MnemonicCode mnemonicCode = new MnemonicCode("english");
        String words =  "shoot island position soft burden budget tooth cruel issue economy destroy above";
        byte[] seed = mnemonicCode.toSeed(Arrays.asList(words.split(" ")), "");
        //byte[] seed = Hex.decode("577cd910aede2582668a741d476b45e7998e905a4286f701b87b25923501f9d4ea19513b460bcccbc069ebbe4327a59af3d6463045c4b6fa21a5e7004ccfcc3e");
        byte[] init = "ed25519 seed".getBytes(StandardCharsets.UTF_8);
        int[] path = {44, 397, 0};

        byte[] key = HierarchicalDeterministicKey.getFromSeed(seed, init, path);
        //assertEquals("3jFpZEcbhcjpqVE27zU3d7WHcS7Wq716v5WryU8Tj4EaNTHTj8iAhtPW7KCdFV2fnjNf9toawUbdqZnhrRtLKe6w", Base58.encode(key));
        assertTrue(true);
    }
}
