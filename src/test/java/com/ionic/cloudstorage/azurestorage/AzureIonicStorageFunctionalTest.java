/*
 * (c) 2019 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import static org.junit.Assert.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringBufferInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.nio.file.InvalidPathException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.IonicException;

import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;



public class AzureIonicStorageFunctionalTest {

    private static String mAccountName;
    private static String mAccountKey;
    private static String mStorageConnectionString;

    private static CloudStorageAccount mCloudStorageAccount;
    private static CloudBlobClient mCloudBlobClient;
    
    private static AzureIonicStorage mAzureIonicStorage;
    private static DeviceProfilePersistorPlainText mPlaintextPersistor;
    
    private static String mContainerName = System.getenv("IONIC_AZURE_STORAGE_TEST_CONTAINER");
    private static String mBlobName = "test";
    
    private static String mOriginalBlobContent;
    private static byte[] mOriginalBlobBytes;

    @BeforeClass
    public static void init()
            throws InvalidPathException, IOException, UnsupportedEncodingException, IonicException {
        
        // Retrieve and Initialize Azure Shared Key Credentials
        //    Account Name - AZURE_STORAGE_ACCOUNT
        //    Account Key - AZURE_STORAGE_ACCESS_KEY
        // Obtained from https://portal.azure.com/#home
        //    Select Storage Accounts
        //    Select Your Storage Account
        //    Select Access Keys
        //    Copy Key and Connection string from active key
        //    export to env
        try {
            // Retrieve and initialize shared key credentials
            mAccountName = System.getenv("AZURE_STORAGE_ACCOUNT");
            mAccountKey = System.getenv("AZURE_STORAGE_ACCESS_KEY");
            mStorageConnectionString = "DefaultEndpointsProtocol=https;" + "AccountName="
                    + mAccountName + ";" + "AccountKey=" + mAccountKey;
        } catch (NullPointerException npe) {
            System.err.println("Missing Azure Storage Account Info");
            return;
        } catch (SecurityException se) {
            System.err.println("Insufficient privelege to obtain Azure Storage Account Info");
            return;
        }

        try {
            mCloudStorageAccount = CloudStorageAccount.parse(mStorageConnectionString);
            mCloudBlobClient = mCloudStorageAccount.createCloudBlobClient();
        } catch (InvalidKeyException invalidKeyException) {
            System.err.print("InvalidKeyException encountered: ");
            System.err.println(invalidKeyException.getMessage());
        } catch (URISyntaxException uriSyntaxException) {
            System.err.print("URISyntaxException encountered: ");
            System.err.println(uriSyntaxException.getMessage());
        } catch (Exception e) {
            System.err.print("Exception encountered: ");
            System.err.println(e.getMessage());
        }

        // set cloud blob client to require encryption
        mCloudBlobClient.getDefaultRequestOptions().setRequireEncryption(true);

        // Load plaintext persistor
        // Note: use of plaintext persistor is for demonstration only
        //       see documentation for use of default, password, or aesgcm persistor types
        mPlaintextPersistor = new DeviceProfilePersistorPlainText();
        String sProfilePath =
                Paths.get(System.getProperty("user.home") + "/.ionicsecurity/profiles.pt").toFile()
                        .getCanonicalPath();
        mPlaintextPersistor.setFilePath(sProfilePath);

        mAzureIonicStorage = new AzureIonicStorage(mPlaintextPersistor);

        mOriginalBlobContent = "This is the functional test blob";
        mOriginalBlobBytes = mOriginalBlobContent.getBytes("UTF-8");

    }

    @Test
    public void createAndReadRoundtrip() throws UnsupportedEncodingException {

        try {
            // Note: Container name must be lower case.
            CloudBlobContainer mCloudBlobContainer = mCloudBlobClient.getContainerReference(mContainerName);
            mCloudBlobContainer.createIfNotExists();

            // Upload an string.
            CloudBlockBlob blob = mCloudBlobContainer.getBlockBlobReference(mBlobName);

            // Create the IKey used for encryption.
            SymmetricKey key = mAzureIonicStorage.create();

            // Create the encryption policy to be used for upload and download.
            BlobEncryptionPolicy blobEncryptionPolicy = new BlobEncryptionPolicy(key, null);

            // Set the encryption policy on the request options.
            BlobRequestOptions blobRequestOptions = new BlobRequestOptions();
            blobRequestOptions.setEncryptionPolicy(blobEncryptionPolicy);

            // Upload the encrypted contents to the blob.
            blob.upload(new StringBufferInputStream(mOriginalBlobContent), mOriginalBlobContent.length(), null, blobRequestOptions, null);

            
            // Download and decrypt the encrypted contents from the blob.
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            blob.download(byteArrayOutputStream, null, blobRequestOptions, null);
            byte[] downloadedBlobBytes = byteArrayOutputStream.toByteArray();

            String assertMessage = "Create and Read Roundtrip Failed";
            assertArrayEquals(assertMessage, mOriginalBlobBytes, downloadedBlobBytes);
        } catch (Exception e) {
            System.err.print("Exception encountered: ");
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    @Test
    public void readPreviousUpload() throws UnsupportedEncodingException {

        try {
            // Note: Container name must be lower case.
            CloudBlobContainer mCloudBlobContainer = mCloudBlobClient.getContainerReference(mContainerName);

            // Upload an string.
            CloudBlockBlob blob = mCloudBlobContainer.getBlockBlobReference(mBlobName);

            // Create the IKey used for encryption.
            SymmetricKey key = mAzureIonicStorage.create();

            // Create the encryption policy to be used for upload and download.
            // Use KeyResolver to obtain IKey for decryption
            BlobEncryptionPolicy downloadPolicy = new BlobEncryptionPolicy(null, mAzureIonicStorage.getKeyResolver());

            // Set the encryption policy on the request options.
            BlobRequestOptions blobRequestOptions = new BlobRequestOptions();
            blobRequestOptions.setEncryptionPolicy(downloadPolicy);

            // Download and decrypt the previously encrypted contents from the blob.
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            blob.download(byteArrayOutputStream, null, blobRequestOptions, null);
            byte[] downloadedBlobBytes = byteArrayOutputStream.toByteArray();

            String assertMessage = "Read of Previous Upload Failed";
            assertArrayEquals(assertMessage, mOriginalBlobBytes, downloadedBlobBytes);
        } catch (Exception e) {
            System.err.print("Exception encountered: ");
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

}
