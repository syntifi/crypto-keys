package com.syntifi.crypto.key.deterministic;

import com.syntifi.crypto.key.encdec.Hex;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

//hMac.init(new KeyParameter("ed25519 seed".getBytes(StandardCharsets.UTF_8)));

/**
 * The procedure to implement BIP32 or SLIP 10 to generate deterministic keys hierarchically
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 *
 * @author Alexandre Carvalho
 * @author Andre Bertolace
 * @since 0.2.0
 */
public class HierarchicalDeterministicKey {
    private final static Long MAX_VALUE_INDEX = 2147483648L;

    public static byte[] getFromSeed(byte[] seed, byte[] init, int[] derivationPath) throws IOException {
        byte[] result = HierarchicalDeterministicKey.getMasterKeyFromSeed(seed, init);
        byte[] key;
        byte[] chainCode;
        key = Arrays.copyOfRange(result, 0, 32);
        chainCode = Arrays.copyOfRange(result, 32, 64);
        for (int i : derivationPath) {
            byte[] keyi = HierarchicalDeterministicKey.childKeyDerivation(
                    key, chainCode, HierarchicalDeterministicKey.longToBytes(MAX_VALUE_INDEX + i));
            key = Arrays.copyOfRange(keyi, 0, 32);
            chainCode = Arrays.copyOfRange(keyi, 32, 64);
        }
        return key;
    }

    /**
     *
     * @param seed bytes
     * @param key initial Hmac value
     * @return byte array
     */
    public static byte[] getMasterKeyFromSeed(byte[] seed, byte[] key) {
        HMac hMac = new HMac(new SHA512Digest());
        hMac.init(new KeyParameter(key));
        hMac.update(seed, 0, seed.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return result;
    }

    public static byte[] childKeyDerivation(byte[] key, byte[] chainCode, byte[] index) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(Hex.decode("00"));
        os.write(key);
        os.write(Arrays.copyOfRange(index, 4, 8));
        HMac hMac = new HMac(new SHA512Digest());
        hMac.init(new KeyParameter(chainCode));
        hMac.update(os.toByteArray(), 0, os.size());
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return result;
    }

    private static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
}
