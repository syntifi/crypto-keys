package com.syntifi.crypto.key.hash;

import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Sha256 Hash helper class
 *
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.2.0
 */
public final class Sha256 {
    public static byte[] digest(byte[] input) {
        SHA256Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }
}
