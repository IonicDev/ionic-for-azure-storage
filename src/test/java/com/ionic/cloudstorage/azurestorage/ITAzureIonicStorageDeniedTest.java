/*
 * (c) 2019-2021 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringBufferInputStream;
import java.net.URISyntaxException;

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
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.Test;


public class ITAzureIonicStorageDeniedTest {

    static Logger log = LogManager.getLogger();

    private static CloudBlobClient client = null;
    private static CloudBlobContainer container = null;
    private static IonicKeyResolverFactory ionicKeyResolverFactory = null;
    private static String storageAccount = null;
    private static String testContainerString = null;
    private static String testString = null;

    @BeforeClass
    public static void setup() {
        try {
            client = TestUtils.getCloudBlobClient();
            ionicKeyResolverFactory = TestUtils.getIonicKeyResolverFactory();
            testContainerString = TestUtils.getTestContainer();
            container = client.getContainerReference(testContainerString);
        } catch (Exception e) {
            // Catch any Exceptions thrown during setup and null related objects so
            // that dependent tests are each skipped during the preconditions check.
            log.warn(e.getLocalizedMessage());
            ionicKeyResolverFactory = null;
            testContainerString = null;
            container = null;
        }
        storageAccount = TestUtils.getAzureAccount();
        testString = TestUtils.getTestPayload();
    }

    @Before
    public void preconditions() {
        assertNotNull("Precondition failure, no IonicKeyResolverFactory", ionicKeyResolverFactory);
        assertNotNull("Precondition failure, no Container specified", testContainerString);
        assertNotNull("Precondition failure, no Container Object", container);
        assertNotNull("Precondition failure, no Azure Storage Account specified", storageAccount);
        assertNotNull("Precondition failure, no String payload", testString);
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void uploadAndDownloadBytes() throws Throwable {
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

        thrown.expect(IonicException.class);
        thrown.expectMessage("40024 - Key fetch or creation was denied by the server");

        try {
            blob.download(byteArrayOutputStream, null, blobRequestOptions, null);
        } catch (StorageException e) {
            // Get and throw the nested IonicException
            // StorageException => ExecutionException => IonicException
            throw e.getCause().getCause();
        }
    }

}
