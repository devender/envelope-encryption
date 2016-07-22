package com.gdr.kms.vault;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by dgollapally on 7/18/16.
 *  This is only for testing purpose, it bring up vault in dev mode so that tests can run and then be shutoff.
 */
public class VaultProcess implements Closeable{

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultProcess.class);
    private static final String UNSEAL_KEY = "Unseal Key:";
    private static final String ROOT_TOKEN = "Root Token:";

    private Process vaultProcess;
    private String unSealKey;
    private String rootToken;

    public String getRootToken(){
        return rootToken;
    }

    public String getUnSealKey() {
        return unSealKey;
    }

    public static final VaultProcess init(){
        VaultProcess vaultProcess = new VaultProcess();
        vaultProcess.start();
        vaultProcess.mountTransit();
        return vaultProcess;
    }

    private void mountTransit(){
        LOGGER.info("mount transit");
        ProcessBuilder pb = new ProcessBuilder("vault", "mount", "transit");
        Map<String,String> map = pb.environment();
        map.put("VAULT_ADDR","http://127.0.0.1:8200");
        try {
            Process p = pb.inheritIO().start();
            p.waitFor();
        } catch (IOException e) {
            LOGGER.error("unable to start vault in new process", e);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    public void start() {
        startInternal();
        try {
            //Give time to initialize
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        extractUnsealKeyAndToken();
    }

    private void startInternal() {
        LOGGER.info("starting vault");
        ProcessBuilder pb = new ProcessBuilder("vault", "server", "-dev");
        try {
            vaultProcess = pb.start();
        } catch (IOException e) {
            LOGGER.error("unable to start vault in new process", e);
        }
    }

    private void extractUnsealKeyAndToken() {
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(vaultProcess.getInputStream()));
        StringBuilder builder = new StringBuilder();
        String line = null;
        int linesRead = 0;

        try {
            while ((line = reader.readLine()) != null) {
                builder.append(line);
                builder.append(System.getProperty("line.separator"));
                if (line.contains(UNSEAL_KEY)) {
                    String tmp = line.replace(UNSEAL_KEY, "");
                    unSealKey = tmp.trim();
                } else if (line.contains(ROOT_TOKEN)) {
                    String tmp = line.replace(ROOT_TOKEN, "");
                    rootToken = tmp.trim();
                }
                linesRead++;
                if (linesRead > 20) {
                    break;
                }
            }
        } catch (IOException e) {
            LOGGER.error("unable to read vault output ", e);
        }

        String result = builder.toString();

        LOGGER.debug("Unseal Key {}", unSealKey);
        LOGGER.debug("Root Token {}", rootToken);
        LOGGER.debug(result);
    }

    @Override
    public void close() throws IOException {
        LOGGER.info("stoping vault");
        vaultProcess.destroy();
    }
}
