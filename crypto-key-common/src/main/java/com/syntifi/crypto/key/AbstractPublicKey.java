package com.syntifi.crypto.key;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Data
@NoArgsConstructor
@AllArgsConstructor
public abstract class AbstractPublicKey {
    private byte[] key;

    public abstract void readPublicKey(String filename) throws IOException;

    public abstract void writePublicKey(String filename) throws IOException;

    public abstract Boolean verify(String message, String signature) throws GeneralSecurityException;
}
