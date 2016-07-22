package com.gdr.kms.aws;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.gdr.kms.EnvelopeEncryptedMessage;
import com.gdr.kms.EnvelopeEncryptionService;
import com.gdr.kms.aws.AWSEnvelopeEncryptionServiceImpl;
import org.junit.Assert;
import org.junit.Test;


/**
 * Created by dgollapally on 7/14/16.
 */
public class TestAWSEnvelopeEncryptionServiceImpl {
    private final String namedClientKey = "arn:aws:kms:us-west-1:324671914464:key/510f222f-fbb8-46aa-9408-a329fbb15575";

    @Test
    public void testEncryptAndDecrypt() {

        String testMessage = "Hello World";
        AWSCredentials awsCredentials = null;

        try {
            awsCredentials = new ProfileCredentialsProvider().getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException("Cannot load properties please check ~/.aws/credentials", e);
        }

        EnvelopeEncryptionService encryptionService = new AWSEnvelopeEncryptionServiceImpl(awsCredentials, com.gdr.kms.KmsRegionEndPoint.us_west_1, namedClientKey);

        EnvelopeEncryptedMessage encryptedMessage = encryptionService.encrypt(testMessage);

        String actual = encryptionService.decrypt(encryptedMessage);

        Assert.assertEquals(testMessage, actual);
    }
}
