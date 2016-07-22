package com.gdr.kms.aws;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.gdr.kms.EnvelopeEncryptedMessage;
import com.gdr.kms.EnvelopeEncryptionService;
import com.gdr.kms.KmsRegionEndPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by dgollapally on 7/14/16.
 * <p/>
 * Implementation of EnvelopeEncryptionService that uses AWS as the Key Management System.
 * Each instance of this class expects namedClientKey i.e the name of the Client Master key and the AWS region where this master key exists.
 */
public class AWSEnvelopeEncryptionServiceImpl implements EnvelopeEncryptionService {
    private static final String KEY_TYPE = "AES";
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private final IvParameterSpec ivspec = new IvParameterSpec(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});

    private final String namedClientKey;
    private final AWSKMSClient awskmsClient;


    /**
     * @param awsCredentials to be used by this instance
     * @param regionEndPoint this should match where the client master key is present, master keys are region specific.
     * @param namedClientKey defines the master key to be used for encrypt/decrypt messages. Data keys are generated
     *                       using this namedClientKey. Named Master Key only represents the name of the master key not the actual key itself.
     */
    public AWSEnvelopeEncryptionServiceImpl(final AWSCredentials awsCredentials, final KmsRegionEndPoint regionEndPoint, final String namedClientKey) {
        this.namedClientKey = namedClientKey;
        awskmsClient = new AWSKMSClient(awsCredentials);
        awskmsClient.setEndpoint(regionEndPoint.getUrl());
    }

    /**
     * Sends request to aws to generate a data key using the Client Master Key, configured in this class.
     *
     * @return GenerateDataKeyResult the generated plain text key and its encrypted version.
     */
    private GenerateDataKeyResult generateDataKey() {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(namedClientKey);
        generateDataKeyRequest.setKeySpec(DataKeySpec.AES_128);
        GenerateDataKeyResult dataKeyResult = awskmsClient.generateDataKey(generateDataKeyRequest);
        return dataKeyResult;
    }

    private EnvelopeEncryptedMessage encryptMessage(final String message, final GenerateDataKeyResult dataKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        SecretKeySpec key = new SecretKeySpec(dataKey.getPlaintext().array(), KEY_TYPE);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

        byte[] enc = cipher.doFinal(message.getBytes());

        String cipherText = Base64.getEncoder().encodeToString(enc);

        EnvelopeEncryptedMessage envelope = new EnvelopeEncryptedMessage();
        envelope.setEncryptedKey(dataKey.getCiphertextBlob().array());
        envelope.setCiphertext(cipherText);
        return envelope;
    }

    /**
     * <ul>
     * <li>Generate data key using the master key. Since master key is not available locally we have to send request to aws</li>
     * <li>AWS will return a data key along with its encrypted version</li>
     * <li>Using the plain text key (sent back from aws) encrypt the message</li>
     * <li>Base64 encode the encrypted message</li>
     * <li>Save the encrypted message along with the encrypted data key</li>
     * </ul>
     *
     * @param message to encrypt
     * @return EnvelopeEncryptedMessage return the envolope that contains both the encrypted message and the encrypted data key.
     */
    public EnvelopeEncryptedMessage encrypt(final String message) {
        try {
            GenerateDataKeyResult keyResult = generateDataKey();
            return encryptMessage(message, keyResult);
        } catch (Exception e) {
            throw new RuntimeException("unable to encrypt", e);
        }
    }

    private String decrypt(final SecretKeySpec secretKeySpec, final String cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] decodeBase64src = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
        return new String(cipher.doFinal(decodeBase64src));
    }

    private SecretKeySpec decryptKey(final EnvelopeEncryptedMessage envelope) {
        ByteBuffer encryptedKey = ByteBuffer.wrap(envelope.getEncryptedKey());
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(encryptedKey);
        ByteBuffer plainTextKey = awskmsClient.decrypt(decryptRequest).getPlaintext();
        SecretKeySpec key = new SecretKeySpec(plainTextKey.array(), KEY_TYPE);
        return key;
    }

    /**
     * <ul>
     * <li>Decrypt the Data Key stored in the envelope by calling AWS</li>
     * <li>Base64 Decode the Message stored in the envelope</li>
     * <li>Decrypt the message using the plain text data key obtained in step 1</li>
     * </ul>
     *
     * @param envelope The envlope to be decrypted
     * @return String the decrypted string
     */
    public String decrypt(final EnvelopeEncryptedMessage envelope) {
        try {
            SecretKeySpec key = decryptKey(envelope);
            String text = decrypt(key, envelope.getCiphertext());
            return text;
        } catch (Exception e) {
            throw new RuntimeException("unable to decrypt", e);
        }
    }
}
