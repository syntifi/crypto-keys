package com.syntifi.crypto.key.checksum;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MixedCaseChecksumTest {

    @Test
    void shouldMatchLowerCaseAddress() {
        assertEquals("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                MixedCaseChecksum.checksumEncode("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359"));
    }

    @Test
    void shouldMatchUpperCaseAddress() {
        assertEquals("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                MixedCaseChecksum.checksumEncode("0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359"));
    }

    @Test
    void kekkac256ShouldMatch() {
        assertEquals("a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b",
                MixedCaseChecksum.kekkac256("transfer(address,uint256)"));
    }
}
