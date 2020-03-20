/*
 * (c) 2020 Ionic Security Inc. By using this code, I agree to the LICENSE included, as well as the
 * Terms & Conditions (https://dev.ionic.com/use) and the Privacy Policy
 * (https://ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.samples;

import com.ionic.cloudstorage.azurestorage.IonicKeyResolverFactory;
import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPassword;
import com.ionic.sdk.error.IonicException;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;

/**
 * A hello world example using the GoogleIonicStorage client.
 */
public class HelloWorld {

    private static final String HOME = System.getProperty("user.home");

    public static void main(String... args) {
        // read persistor password from environment variable
        String persistorPassword = System.getenv("IONIC_PERSISTOR_PASSWORD");
        if (persistorPassword == null) {
            System.out.println("[!] Please provide the persistor password as env variable:"
                    + " IONIC_PERSISTOR_PASSWORD");
            System.exit(1);
        }

        // initialize agent
        Agent agent = new Agent();
        try {
            String persistorPath = System.getProperty("user.home") + "/.ionicsecurity/profiles.pw";
            DeviceProfilePersistorPassword persistor =
                    new DeviceProfilePersistorPassword(persistorPath);
            persistor.setPassword(persistorPassword);
            agent.initialize(persistor);
        } catch (IonicException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // initialize a new IonicKeyResolverFactory
        IonicKeyResolverFactory keyResolverFactory = new IonicKeyResolverFactory(agent);

        // accountName and accountKey must be to the name and key for your Azure Storage Account
        String accountName = "my Azure Storage Account Name";
        String accountKey = "my Azure Storage Account Key";

        // Build Storage Connection String from Name and Key
        String storageConnectionString = "DefaultEndpointsProtocol=https;" + "AccountName="
                + accountName + ";" + "AccountKey=" + accountKey;

        // Create CloudBlobClient
        CloudStorageAccount account = null;
        try {
            account = CloudStorageAccount.parse(storageConnectionString);
        } catch (URISyntaxException | InvalidKeyException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        CloudBlobClient serviceClient = account.createCloudBlobClient();

        String containerName = "my Container";
        String blobName = "my Blob";

        // Upload a string

        // Create the Container object
        CloudBlobContainer container = null;
        try {
            container = serviceClient.getContainerReference(containerName);
        } catch (URISyntaxException | StorageException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        // Create the Blob Object in the Container
        CloudBlockBlob blob = null;
        try {
            blob = container.getBlockBlobReference(blobName);
        } catch (URISyntaxException | StorageException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        // Create the IKey used for encryption.
        SymmetricKey key = null;
        try {
            key = keyResolverFactory.create();
        } catch (IonicException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // Create the encryption policy to be used for upload.
        BlobEncryptionPolicy uploadPolicy = new BlobEncryptionPolicy(key, null);

        // Set the encryption policy on the request options.
        BlobRequestOptions uploadOptions = new BlobRequestOptions();
        uploadOptions.setEncryptionPolicy(uploadPolicy);

        // Upload the encrypted contents to the blob.
        String helloWorld = "Hello World!";
        try {
            blob.uploadText(helloWorld, null, null, uploadOptions, null);
        } catch (StorageException | IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        //Download a string

        // Create the encryption policy to be used for download.
        IonicKeyResolverFactory.IonicKeyResolver keyResolver =
                keyResolverFactory.createKeyResolver();
        BlobEncryptionPolicy downloadPolicy = new BlobEncryptionPolicy(null, keyResolver);

        // Set the encryption policy on the request options.
        BlobRequestOptions downloadOptions = new BlobRequestOptions();
        downloadOptions.setEncryptionPolicy(downloadPolicy);

        // CloudBlockBlob must be created as in previous steps if not already present

        String downloadString = null;
        try {
            downloadString = blob.downloadText(null, null, downloadOptions, null);
        } catch (StorageException | IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

        // print string to standard out
        System.out.println(downloadString);

        // exit
        System.exit(0);
    }
}
