package com.gdr.kms.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.gdr.kms.EnvelopeEncryptedMessage;
import com.gdr.kms.EnvelopeEncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by dgollapally on 7/18/16.
 * <p/>
 * Implementation of EnvelopeEncryptionService that uses Vault as the Key Management System.
 * Each instance of this class expects namedClientKey i.e the name of the Client Master key and configuration to connect to Vault.
 */
public class VaultEnvelopeEncryptionImpl implements EnvelopeEncryptionService {

    private static final String KEY_TYPE = "AES";
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private final IvParameterSpec ivspec = new IvParameterSpec(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});

    private static final String CIPHERTEXT = "ciphertext";
    private static final Logger LOGGER = LoggerFactory.getLogger(VaultEnvelopeEncryptionImpl.class);
    private static final String PLAINTEXT = "plaintext";

    private final Vault vault;
    private final String namedClientKey;
    private final String vaultPathGenerateDateKey;
    private final String vaultPathDecryptDataKey;



    /**
     * @param vaultConfig    Configuration required to connect to Vault.
     * @param namedClientKey defines the master key to be used for encrypt/decrypt messages. Data keys are generated
     *                       using this namedClientKey. Named Master Key only represents the name of the master key not the actual key itself.
     */
    public VaultEnvelopeEncryptionImpl(final VaultConfig vaultConfig, final String namedClientKey) {
        vault = new Vault(vaultConfig);
        this.namedClientKey = namedClientKey;

        //NOTE the data keys are generated and decrypted based on the client master key used.
        this.vaultPathGenerateDateKey = "transit/datakey/plaintext/" + namedClientKey;
        this.vaultPathDecryptDataKey = "transit/decrypt/" + namedClientKey;
    }

    /**
     * <ul>
     * <li>Using the Named Master Key configured for this call , this method will first generate a data key.</li>
     * <li>Using the data key generated in the above step it will encrypt the given message.</li>
     * </ul>
     *
     * @param message The string message to be encrypted
     * @return EnvelopeEncryptedMessage the envelope that contains both the encrypted message and the encrypted key that was used to encrypt the message.
     */
    @Override
    public EnvelopeEncryptedMessage encrypt(final String message) {
        try {
            //generate a data key
            VaultGeneratedDataKeyResult keyResult = generateDataKey();
            //use the data key to encrypt
            return encryptMessage(message, keyResult);
        } catch (Exception e) {
            throw new RuntimeException("unable to encrypt", e);
        }
    }

    private EnvelopeEncryptedMessage encryptMessage(final String message, final VaultGeneratedDataKeyResult dataKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //the text returned by vault is always base64 encoded hence we have to decode it to get plain string.
        byte[] decodeBase64src = Base64.getDecoder().decode(dataKey.getPlaintext().getBytes());

        //using the plain text key obtained we can encrypt the message
        SecretKeySpec key = new SecretKeySpec(decodeBase64src, KEY_TYPE);
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

        byte[] enc = cipher.doFinal(message.getBytes());
        String cipherText = Base64.getEncoder().encodeToString(enc);

        EnvelopeEncryptedMessage envelope = new EnvelopeEncryptedMessage();
        envelope.setEncryptedKey(dataKey.getCiphertext().getBytes());
        envelope.setCiphertext(cipherText);

        return envelope;
    }

    private VaultGeneratedDataKeyResult generateDataKey() throws VaultException {
        Map<String, String> options = new HashMap<>(1);
        options.put("bits", "128");
        LogicalResponse response = vault.logical().write(vaultPathGenerateDateKey, options);
        Map<String, String> map = response.getData();
        return VaultGeneratedDataKeyResult.builder().withCipherText(map.get(CIPHERTEXT)).withPlainText(map.get(PLAINTEXT)).build();
    }

    /**
     * Get the plain text key used to encrypt the message
     *
     * @param envelope
     * @return SecretKeySpec
     * @throws VaultException
     */
    private SecretKeySpec decryptKey(final EnvelopeEncryptedMessage envelope) throws VaultException {
        Map<String, String> map = new HashMap<>();
        map.put(CIPHERTEXT, new String(envelope.getEncryptedKey()));

        LogicalResponse response = vault.logical().write(vaultPathDecryptDataKey, map);

        //since vault always returns in base64
        byte[] decodeBase64src = Base64.getDecoder().decode(response.getData().get(PLAINTEXT).getBytes());

        SecretKeySpec key = new SecretKeySpec(decodeBase64src, KEY_TYPE);
        return key;
    }

    private String decrypt(final SecretKeySpec secretKeySpec, final String cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] decodeBase64src = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
        return new String(cipher.doFinal(decodeBase64src));
    }

    @Override
    public String decrypt(EnvelopeEncryptedMessage envelope) {
        try {
            SecretKeySpec secretKeySpec = decryptKey(envelope);
            String text = decrypt(secretKeySpec, envelope.getCiphertext());
            return text;
        } catch (Exception e) {
            throw new RuntimeException("unable to decrypt", e);
        }
    }
}
