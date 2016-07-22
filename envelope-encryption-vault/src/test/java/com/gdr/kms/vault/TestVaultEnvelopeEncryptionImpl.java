package com.gdr.kms.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.gdr.kms.EnvelopeEncryptedMessage;
import com.gdr.kms.EnvelopeEncryptionService;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


import java.io.IOException;
import java.util.HashMap;

/**
 * Created by dgollapally on 7/18/16.
 */
public class TestVaultEnvelopeEncryptionImpl {

    private static final String namedKey = "foo";

    private VaultProcess vaultProcess;
    private VaultConfig vaultConfig;


    @Before
    public void before() throws VaultException {
        vaultProcess = VaultProcess.init();

        vaultConfig = new VaultConfig()
                .token(vaultProcess.getRootToken())
                .address("http://127.0.0.1:8200")
                .build();

        Vault vault = new Vault(vaultConfig);

        String namedClientKey = "transit/keys/" + namedKey;
        LogicalResponse response = vault.logical().write(namedClientKey, new HashMap<String, String>());
    }

    @After
    public void after() throws IOException {
        if (null != vaultProcess) {
            vaultProcess.close();
        }
    }

    @Test
    public void testEncryptAndDecrypt() throws VaultException, IOException {
        EnvelopeEncryptionService encryptionService = new VaultEnvelopeEncryptionImpl(vaultConfig,namedKey);

        String testMessage = "Hello World";

        EnvelopeEncryptedMessage encryptedMessage = encryptionService.encrypt(testMessage);

        String actual = encryptionService.decrypt(encryptedMessage);

        Assert.assertEquals(testMessage, actual);
    }
}
