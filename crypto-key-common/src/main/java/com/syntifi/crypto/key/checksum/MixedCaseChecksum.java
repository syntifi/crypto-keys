package com.syntifi.crypto.key.checksum;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;

/**
 * Implementation of the EIP-55: Mixed-case checksum address encoding
 * Documentation available at: https://eips.ethereum.org/EIPS/eip-55
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.5.0
 */
public class MixedCaseChecksum {

    public static String kekkac256(String value) {
        Keccak.DigestKeccak kekkac256 = new Keccak.Digest256();
        byte[] hash = kekkac256.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    public static String checksumEncode(String address) {
        Boolean withPrefix = address.startsWith("0x");
        String value = address.toLowerCase().replace("0x", "");
        char[] hash = kekkac256(value).toCharArray();
        char[] chars = value.toCharArray();
        char[] encoded = new char[chars.length];
        for (int i = 0; i < chars.length; i++) {
            encoded[i] = Character.digit(hash[i], 16) > 7
                    ? Character.toUpperCase(chars[i])
                    : chars[i];
        }
        return withPrefix
                ? "0x" + String.valueOf(encoded)
                : String.valueOf(encoded);
    }

}
