package com.syntifi.crypto.key.mnemonic;

import com.syntifi.crypto.key.AbstractCryptoTests;
import com.syntifi.crypto.key.encdec.Hex;
import com.syntifi.crypto.key.mnemonic.exception.MnemonicException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * examples at
 * https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch05.asciidoc#creating-an-hd-wallet-from-the-seed
 *
 * comparing with the output from
 * https://iancoleman.io/bip39/
 */
public class MnemonicCodeTest extends AbstractCryptoTests {
    private static final Logger LOGGER = LoggerFactory.getLogger(MnemonicCodeTest.class);

    @Test
    void getSeedFromWordlist_seed_should_match() throws IOException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicLengthException {
        String words = "army van defense carry jealous true garbage claim echo media make crunch";
        List<String> wordList = Arrays.asList(words.split(" "));
        MnemonicCode mnemonicCode = new MnemonicCode("english");
        byte[] seed = mnemonicCode.toSeed(wordList, "");
        assertEquals("5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570", Hex.encode(seed));
    }

    @Test
    void getEntropyFromWordlist_entropy_should_match() throws IOException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicLengthException {
        String words = "army van defense carry jealous true garbage claim echo media make crunch";
        List<String> wordList = Arrays.asList(words.split(" "));
        MnemonicCode mnemonicCode = new MnemonicCode("english");
        byte[] entropy = mnemonicCode.toEntropy(wordList);
        assertEquals("0c1e24e5917779d297e14d45f14e1a1a", Hex.encode(entropy));
    }

    @Test
    void getWordListFromEntropy_words_should_match() throws IOException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicLengthException {
        MnemonicCode mnemonicCode = new MnemonicCode("english");
        List<String> w = mnemonicCode.toMnemonic(Hex.decode("0c1e24e5917779d297e14d45f14e1a1a"));
        String words = "army van defense carry jealous true garbage claim echo media make crunch";
        List<String> wordList = Arrays.asList(words.split(" "));
        assertEquals(w, wordList);
    }

    @Test
    void generateRandomList_should_generate_12_words() throws IOException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicLengthException {
        List<String> words = MnemonicCode.generateSecureRandomWords("english");
        assertEquals(12, words.size());
    }
}
