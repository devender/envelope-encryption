package com.gdr.kms;

/**
 * Created by dgollapally on 7/14/16.
 * <p/>
 * A simple POJO that contains:
 * <ul>
 * <li>The encrypted message.</li>
 * <li>And the (encrypted) data key that was used to encrypt message.</li>
 * </ul>
 */
public class EnvelopeEncryptedMessage {
    private byte[] encryptedKey;
    private String ciphertext;

    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getCiphertext() {
        return ciphertext;
    }
}
