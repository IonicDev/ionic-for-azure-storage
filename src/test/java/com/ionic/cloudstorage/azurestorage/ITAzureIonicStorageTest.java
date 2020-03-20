/*
 * (c) 2019-2020 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringBufferInputStream;
import java.net.URISyntaxException;
import java.util.Arrays;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.agent.request.getkey.GetKeysResponse;
import com.ionic.sdk.error.IonicException;

import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.StorageException;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


public class ITAzureIonicStorageTest {

    static Logger log = LogManager.getLogger();

    private static CloudBlobClient client = null;
    private static CloudBlobContainer container = null;
    private static Agent agent = null;
    private static IonicKeyResolverFactory ionicKeyResolverFactory = null;
    private static String storageAccount = null;
    private static String testContainerString = null;
    private static String testString = null;

    @BeforeClass
    public static void setup() {
        try {
            client = TestUtils.getCloudBlobClient();
            agent = TestUtils.getAgent();
            ionicKeyResolverFactory = TestUtils.getIonicKeyResolverFactory();
            testContainerString = TestUtils.getTestContainer();
            container = client.getContainerReference(testContainerString);
        } catch (Exception e) {
            // Catch any Exceptions thrown during setup and null related objects so
            // that dependent tests are each skipped during the preconditions check.
            log.warn(e.getLocalizedMessage());
            client = null;
            agent = null;
            ionicKeyResolverFactory = null;
            testContainerString = null;
            container = null;
        }
        storageAccount = TestUtils.getAzureAccount();
        testString = TestUtils.getTestPayload();
    }

    @Before
    public void preconditions() {
        assertNotNull("Precondition failure, no CloudBlobClient", client);
        assertNotNull("Precondition failure, no Ionic agent", agent);
        assertNotNull("Precondition failure, no IonicKeyResolverFactory", ionicKeyResolverFactory);
        assertNotNull("Precondition failure, no Container specified", testContainerString);
        assertNotNull("Precondition failure, no Container Object", container);
        assertNotNull("Precondition failure, no Azure Storage Account specified", storageAccount);
        assertNotNull("Precondition failure, no String payload", testString);
    }


    @Test
    public void uploadAndDownloadBytes() throws IonicException, URISyntaxException,
            StorageException, IOException {
        String blobName = TestUtils.getTestObjectKey();
        if (blobName == null) {
            blobName = "uploadAndDownloadBytes";
        }

        CloudBlockBlob blob = container.getBlockBlobReference(blobName);

        SymmetricKey key = ionicKeyResolverFactory.create();
        BlobEncryptionPolicy blobEncryptionPolicy = new BlobEncryptionPolicy(key, null);
        BlobRequestOptions blobRequestOptions = new BlobRequestOptions();
        blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);
        log.info("Uploading Blob " + blobName + " to container " + testContainerString + " for Storage " + storageAccount +" with Azure Ionic Storage");
        blob.upload(new StringBufferInputStream(testString), testString.length(), null, blobRequestOptions, null);

        blobEncryptionPolicy = new BlobEncryptionPolicy(null, ionicKeyResolverFactory.createKeyResolver());
        blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);
        log.info("Downloading Blob " + blobName + " from container " + testContainerString + " for Storage " + storageAccount +" with Azure Ionic Storage");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, blobRequestOptions, null);
        byte[] downloadedBlobBytes = byteArrayOutputStream.toByteArray();

        assertArrayEquals("Decrypted Blob content does not match original String",
            testString.getBytes(), downloadedBlobBytes);
    }

    @Test
    public void atRestEncryption() throws IonicException, URISyntaxException,
            StorageException, IOException {
        String blobName = TestUtils.getTestObjectKey();
        if (blobName == null) {
            blobName = "atRestEncryption";
        }

        CloudBlockBlob blob = container.getBlockBlobReference(blobName);

        SymmetricKey key = ionicKeyResolverFactory.create();
        BlobEncryptionPolicy blobEncryptionPolicy = new BlobEncryptionPolicy(key, null);
        BlobRequestOptions blobRequestOptions = new BlobRequestOptions();
        blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);
        log.info("Uploading Blob " + blobName + " to container " + testContainerString + " for Storage " + storageAccount +" with Azure Ionic Storage");
        blob.upload(new StringBufferInputStream(testString), testString.length(), null, blobRequestOptions, null);

        log.info("Downloading Blob " + blobName + " from container " + testContainerString + " for Storage " + storageAccount +" with Azure Storage");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, null, null);
        byte[] downloadedBlobBytes = byteArrayOutputStream.toByteArray();

        assertNotEquals("Uploaded blob content matches original String",
            testString, new String(downloadedBlobBytes));
    }

    @Test
    public void uploadBlobWithAttributes() throws IonicException, URISyntaxException,
            StorageException, IOException {
        String blobName = TestUtils.getTestObjectKey();
        if (blobName == null) {
            blobName = "uploadBlobWithAttributes";
        }

        CloudBlockBlob blob = container.getBlockBlobReference(blobName);

        KeyAttributesMap attributes = new KeyAttributesMap();
        KeyAttributesMap mutableAttributes = new KeyAttributesMap();
        attributes.put("Attribute", Arrays.asList("Val1", "Val2", "Val3"));
        mutableAttributes.put("Mutable-Attribute", Arrays.asList("Val1", "Val2", "Val3"));
        CreateKeysRequest.Key ionicRequestKey = new CreateKeysRequest.Key("", 1, attributes, mutableAttributes);

        SymmetricKey key = ionicKeyResolverFactory.create(ionicRequestKey);
        BlobEncryptionPolicy blobEncryptionPolicy = new BlobEncryptionPolicy(key, null);
        BlobRequestOptions blobRequestOptions = new BlobRequestOptions();
        blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);
        log.info("Uploading Blob " + blobName + " to container " + testContainerString + " for Storage " + storageAccount +" with Azure Ionic Storage");
        blob.upload(new StringBufferInputStream(testString), testString.length(), null, blobRequestOptions, null);

        IonicKeyResolverFactory.IonicKeyResolver resolver = ionicKeyResolverFactory.createKeyResolver();
        blobEncryptionPolicy = new BlobEncryptionPolicy(null, resolver);
        blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);
        log.info("Downloading Blob " + blobName + " from container " + testContainerString + " for Storage " + storageAccount +" with Azure Ionic Storage");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, blobRequestOptions, null);
        byte[] downloadedBlobBytes = byteArrayOutputStream.toByteArray();

        GetKeysResponse.Key ionicKey = resolver.getKey();

        assertTrue("Response Key Attributes do not match specified Attributes",
            ionicKey.getAttributesMap().equals(attributes));

        assertTrue("Response Key Mutable Attributes do not match specified Mutable Attributes",
            ionicKey.getMutableAttributesMap().equals(mutableAttributes));

        assertArrayEquals("Decrypted Blob content does not match original String",
            testString.getBytes(), downloadedBlobBytes);
    }

}
