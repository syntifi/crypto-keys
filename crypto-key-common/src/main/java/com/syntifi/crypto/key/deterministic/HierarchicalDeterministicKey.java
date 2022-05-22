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

    private static byte[] getMasterKeyFromSeed(byte[] seed, byte[] init) {
        HMac hMac = new HMac(new SHA512Digest());
        hMac.init(new KeyParameter(init));
        hMac.update(seed, 0, seed.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return result;
    }

    private static byte[] childKeyDerivation(byte[] key, byte[] chainCode, byte[] index) throws IOException {
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
