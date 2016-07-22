package com.gdr.kms.vault;

/**
 * Created by dgollapally on 7/19/16.
 * <p/>
 * Similar to the GenerateDataKeyResult that Amazon API provides. A class which holds the data key in both plain text and encoded format.
 */
public final class VaultGeneratedDataKeyResult {

    private final String ciphertext;
    private final String plaintext;

    public static Builder builder() {
        return new Builder();
    }

    private VaultGeneratedDataKeyResult(final String ciphertext, final String plaintext) {
        this.ciphertext = ciphertext;
        this.plaintext = plaintext;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public String getPlaintext() {
        return plaintext;
    }


    /**
     * Builder for VaultGeneratedDataKeyResult
     */
    public static class Builder {
        private String ciphertext;
        private String plaintext;

        public Builder withCipherText(String ciphertext) {
            this.ciphertext = ciphertext;
            return this;
        }

        public Builder withPlainText(String plainText) {
            this.plaintext = plainText;
            return this;
        }

        public VaultGeneratedDataKeyResult build() {
            return new VaultGeneratedDataKeyResult(ciphertext, plaintext);
        }
    }
}
