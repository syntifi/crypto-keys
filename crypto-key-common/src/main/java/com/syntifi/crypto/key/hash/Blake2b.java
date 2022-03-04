package com.syntifi.crypto.key.hash;

import org.bouncycastle.crypto.digests.Blake2bDigest;

/**
 * Blake2 Hash helper class
 *
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.2.0
 */
public class Blake2b {
    public static byte[] digest(byte[] input) {
        Blake2bDigest d = new Blake2bDigest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }
}
