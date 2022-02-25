package com.syntifi.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Data
@NoArgsConstructor
@AllArgsConstructor
public abstract class AbstractPrivateKey {
    private byte[] key;

    public abstract void readPrivateKey(String filename) throws IOException;

    public abstract void writePrivateKey(String filename) throws IOException;

    public abstract String sign(String message) throws GeneralSecurityException;

    public abstract AbstractPublicKey derivePublicKey();
}
