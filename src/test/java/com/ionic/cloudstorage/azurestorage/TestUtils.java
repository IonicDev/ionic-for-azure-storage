/*
 * (c) 2019-2020 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.AgentErrorModuleConstants;
import com.ionic.sdk.error.IonicException;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;


public class TestUtils {

    static Logger log = LogManager.getLogger();

    protected static String testContainerEnv = "IONIC_AZURE_STORAGE_TEST_CONTAINER";
    protected static String testContainerProp = "testContainer";
    protected static String testAzureAccountEnv = "AZURE_STORAGE_ACCOUNT";
    protected static String testAzureAccountProp = "azureAccount";
    protected static String testAzureKeyEnv = "AZURE_STORAGE_ACCESS_KEY";
    protected static String testAzureKeyProp = "azureKey";
    protected static String testObjectKeyProp = "objectKey";
    protected static String testPayloadStringProp = "payloadString";
    protected static String testPersistorProp = "persistorPath";

    protected static String defaultPayload = "Hello World.";

    protected static String getTestContainer() {
        log.info("Attempting to fetch container name from properties");
        String bucket = System.getProperty(testContainerProp);
        if (bucket == null) {
            log.info("Attempting to fetch container name from environment");
            bucket = System.getenv(testContainerEnv);
        }
        if (bucket == null) {
            log.error("Failed to aquire Container from properties and environment");
        }
        return bucket;
    }

    protected static String getAzureAccount() {
        log.info("Attempting to Azure Storage Account  from properties");
        String account = System.getProperty(testAzureAccountProp);
        if (account == null) {
            log.info("Attempting to Azure Storage Account from environment");
            account = System.getenv(testAzureAccountEnv);
        }
        if (account == null) {
            log.error("Failed to aquire Azure Storage Account from properties and environment");
        }
        return account;
    }

    protected static String getAzureKey() {
        log.info("Attempting to Azure Storage Access Key from properties");
        String key = System.getProperty(testAzureKeyProp);
        if (key == null) {
            log.info("Attempting to Azure Storage Access Key from environment");
            key = System.getenv(testAzureKeyEnv);
        }
        if (key == null) {
            log.error("Failed to aquire Azure Storage Key from properties and environment");
        }
        return key;
    }

    protected static String getTestPayload() {
        String string = System.getProperty(testPayloadStringProp);
        if (string == null) {
            string = defaultPayload;
        }
        return string;
    }

    protected static String getTestObjectKey() {
        return System.getProperty(testObjectKeyProp);
    }

    protected static CloudBlobClient getCloudBlobClient() {
        String account = getAzureAccount();
        String key = getAzureKey();
        if (account == null || key == null) {
            return null;
        }

        String storageConnectionString = "DefaultEndpointsProtocol=https;" + "AccountName="
                + account + ";" + "AccountKey=" + key;

        CloudBlobClient cloudBlobClient = null;

        try {
            cloudBlobClient = CloudStorageAccount.parse(storageConnectionString).createCloudBlobClient();
        } catch (InvalidKeyException | URISyntaxException e) {
            log.error("Exception building CloudBlobClient: " + e.getLocalizedMessage());
            return null;
        }
        return cloudBlobClient;
    }

    protected static IonicKeyResolverFactory getIonicKeyResolverFactory() throws IonicException {
        return new IonicKeyResolverFactory(getAgent());
    }

    protected static DeviceProfilePersistorPlainText getPersistor() throws IonicException {
        DeviceProfilePersistorPlainText ptPersistor = null;
        log.info("Attempting to fetch persistor path from properties");
        String ptPersitorPath = System.getProperty(testPersistorProp);
        if (ptPersitorPath == null) {
            log.info("Attempting to load persistor from default location");
            ptPersitorPath = System.getProperty("user.home") + "/.ionicsecurity/profiles.pt";
        }
        if (Files.exists(Paths.get(ptPersitorPath))) {
            return new DeviceProfilePersistorPlainText(ptPersitorPath);
        } else {
            log.error("Failed to load persistor from " + ptPersitorPath);
            throw new IonicException(AgentErrorModuleConstants.ISAGENT_NO_DEVICE_PROFILE);
        }
    }

    protected static Agent getAgent() throws IonicException {
        log.info("Constructing Ionic Agent with Persisor");
        Agent agent = new Agent();
        agent.initialize(getPersistor());
        return agent;
    }



}
