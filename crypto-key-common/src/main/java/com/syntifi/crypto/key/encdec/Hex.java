package com.syntifi.crypto.key.encdec;

public class Hex {

    public static String encode(byte[] bytes) {
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    public static byte[] decode(String hex) {
        return org.bouncycastle.util.encoders.Hex.decode(hex);
    }

}
