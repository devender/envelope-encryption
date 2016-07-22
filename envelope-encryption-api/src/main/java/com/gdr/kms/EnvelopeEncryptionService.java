package com.gdr.kms;

/**
 * Created by dgollapally on 7/14/16.
 * <p/>
 * Each instance of EnvelopeEncryptionService is expected to be initialized with the namedClientKey to use.
 *
 * namedClientKey are typically keys that are stored in a KMS and never exported out. Applications use the name of the key
 * and the KMS API to generate and decrypt data keys.
 */
public interface EnvelopeEncryptionService {

    /**
     * Will request the underlying Key Management System to generate a data key using what ever ClientKey was configured for this instance.
     * Using the generated datakey will encrypt the message.
     *
     * @param message The string message to be encrypted
     * @return EnvelopeEncryptedMessage
     */
    EnvelopeEncryptedMessage encrypt(final String message);

    /**
     * @param envelope The envelope to be decrypted
     * @return String
     */
    String decrypt(final EnvelopeEncryptedMessage envelope);
}
