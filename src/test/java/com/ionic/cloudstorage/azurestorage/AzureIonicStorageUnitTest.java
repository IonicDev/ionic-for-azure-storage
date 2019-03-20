/*
 * (c) 2019 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringBufferInputStream;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.nio.file.InvalidPathException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.FixMethodOrder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.data.MetadataMap;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.agent.request.createkey.CreateKeysResponse;
import com.ionic.sdk.agent.request.getkey.GetKeysRequest;
import com.ionic.sdk.agent.request.getkey.GetKeysResponse;
import com.ionic.sdk.error.IonicException;

//import com.microsoft.azure.keyvault.core.IKey;
import com.microsoft.azure.keyvault.core.IKeyResolver;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.StorageException;

import com.ionic.cloudstorage.azurestorage.AzureIonicStorage;
import com.ionic.cloudstorage.azurestorage.AzureIonicStorage.KeyResolver;
import com.ionic.cloudstorage.azurestorage.Version;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AzureIonicStorageUnitTest {
    
    // Objects set/used globally during tests
    // Access to Azure Cloud Storage account
    private static String mAccountName;
    private static String mAccountKey;
    private static String mStorageConnectionString;

    private static CloudStorageAccount mCloudStorageAccount;
    private static CloudBlobClient mCloudBlobClient;
    
    private static AzureIonicStorage mAzureIonicStorage;
    
    // Ionic Agent and Key
    private static Agent mIonicAgent;
    private static IonicAgentFactory mIonicAgentFactory;
    private static DeviceProfilePersistorPlainText mPtPersistor;
    private static CreateKeysResponse.Key mIonicKeyCreated;
    private static GetKeysResponse.Key    mIonicKeyFetched;
    
    private static SymmetricKey mSymmetricKey;

    // Azure storage objects used during tests
    private static String mContainerName = System.getenv("IONIC_AZURE_STORAGE_TEST_CONTAINER");
    private static String mBlobName = "test";
    private static String mIonicKeyID = "nokey";
    
    // Test Blob setup
    private static String mOriginalBlobContent;
    private static byte[] mOriginalBlobBytes;
    
    
    private static KeyAttributesMap mBaseKeyAttributesMap;

    /*
     * init() - initialize Azure Storage Cloud access and Ionic connector
     */
    @BeforeClass
    public static void init() throws InvalidPathException, IOException, IonicException {
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

        // Use Credentials to setup Azure cloud storage access
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

        // Initialize mPtPersitor plain text persistor for key generation and retrieval
        mPtPersistor = new DeviceProfilePersistorPlainText();
        String sProfilePath =
                Paths.get(System.getProperty("user.home") + "/.ionicsecurity/profiles.pt").toFile()
                        .getCanonicalPath();
        mPtPersistor.setFilePath(sProfilePath);

        // Initialize mIonicAgentFactory to obtain Agent(s)
        mIonicAgentFactory = new IonicAgentFactory();
        mIonicAgentFactory.setActiveProfile(mPtPersistor);

        mAzureIonicStorage = new AzureIonicStorage(mPtPersistor);

        // Initialize Blob content for use in the tests
        mOriginalBlobContent = "This is the functional test blob";
        mOriginalBlobBytes = mOriginalBlobContent.getBytes("UTF-8");
        
        // Initialize baseKeyAttributesMap 
        mBaseKeyAttributesMap = new KeyAttributesMap();
        String stringAttributes = "attribute1:val1:val2,attribute2:val3";
        String[] pairs = stringAttributes.split(",");
        for (String pair : pairs) {
            String[] tuples = pair.split(":");
            ArrayList<String> values = new ArrayList<String>();
            for (int i = 1; i < tuples.length; i++) {
                values.add(tuples[i]);
            }
            mBaseKeyAttributesMap.put(tuples[0], values);
        }
        
    }

    /*
     * initEach() - get instance of Agent from mIonicAgentFactory
     * pre-req: init() to generate mIonicAgentFactory instance of IonicAgentFactory
     * 
     */
    @Before
    public void initEach() throws IonicException {
        mIonicAgent = mIonicAgentFactory.getAgent();
    }
    
    
    /*
     * test01_GetKeyResolver() - get KeyResolver instance
     */
    @Test
    public void test01_GetKeyResolver() throws Exception {
        assertNotNull(mAzureIonicStorage.getKeyResolver());
    }

    /*
     * test02_CreateKey() - follow process of creating response key
     *     Create request key with KeyId = "ref", request create 1 key, no attributes defined
     *     Use request key to generate response key
     *     assert ionicKeyCreated exists (not null)
     */
    @Test
    public void test02_CreateKey() throws Exception {
        CreateKeysRequest request = new CreateKeysRequest();
        CreateKeysRequest.Key requestKey = new CreateKeysRequest.Key("ref", 1);
        request.getKeys().add(requestKey);
        CreateKeysResponse keysResponse;
        keysResponse = mIonicAgent.createKeys(request);
        assertNotNull(mIonicKeyCreated = keysResponse.getFirstKey());
    }

    /*
     * test03_FetchKey() - follow process for obtaining existing Ionic key
     *     Create key request with KeyId obtained from response key ionicKeyCreated
     *     Use key request to obtain Ionic key
     *     assert ionicKeyFetched exists (not null)
     * pre-req: test01_CreateKey() to obtain ionicKeyCreated
     */
    @Test
    public void test03_FetchKey() throws Exception {
        GetKeysRequest request = new GetKeysRequest();
        request.getKeyIds().add(mIonicKeyCreated.getId());
        GetKeysResponse response = mIonicAgent.getKeys(request);
        assertNotNull(mIonicKeyFetched = response.getFirstKey());
    }
    
    /*
     * test04_CreateSymmetricKey() - creates a CreateKeysResponse.Key and 
     *     translates and returns SymmetricKey with KeyId and Key byte[]
     * 
     */
    @Test
    public void test04_CreateSymmetricKey() throws IonicException {
        CreateKeysRequest.Key requestKey = new CreateKeysRequest.Key("ref", 1);
        SymmetricKey mSymmetricKey = mAzureIonicStorage.create(requestKey);
        assertNotNull(mSymmetricKey);     
    }

    /*
     * test05_UploadBlob() - upload blob to Azure Cloud Storage then
     *                       download with same IKey and verify content matches
     */
    @Test
    public void test05_UploadBlob() throws IonicException, URISyntaxException, StorageException, IOException {
        CloudBlobContainer container = mCloudBlobClient.getContainerReference(mContainerName);
        container.createIfNotExists();
        CloudBlockBlob blob = container.getBlockBlobReference(mBlobName);
        
        // Create the IKey used for encryption.
        SymmetricKey key;

        key = mAzureIonicStorage.create(new CreateKeysRequest.Key("ref", 1));
        
        
        // Create the encryption policy to be used for upload and download.
        //    create with IKey.  (no IKeyResolver)
        BlobEncryptionPolicy policy = new BlobEncryptionPolicy(key, null);
    
        // Set the encryption policy on the request options.
        BlobRequestOptions options = new BlobRequestOptions();
        options.setEncryptionPolicy(policy);
    
        // Upload the encrypted contents to the blob.
        blob.upload(new StringBufferInputStream(mOriginalBlobContent), mOriginalBlobContent.length(), null, options, null);

        // Download and decrypt the encrypted contents from the blob.
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, options, null);
        // Verify downloaded blob matches original string
        assertTrue(byteArrayOutputStream.toString().equals(mOriginalBlobContent));
    }
    
    /*
     * test06_FailResolveKeyBeforeDownload() - Attemp access IKey from
     *                                         KeyResolver prior to download in test 07
     * pre-req: Upload blob to Azure Cloud Storage
     */
    @Test
    public void test06_FailResolveKeyBeforeDownload() throws Exception {
        CloudBlobContainer container = mCloudBlobClient.getContainerReference(mContainerName);
        container.createIfNotExists();
        CloudBlockBlob blob = container.getBlockBlobReference(mBlobName);
        KeyResolver keyResolver = mAzureIonicStorage.getKeyResolver();
        BlobEncryptionPolicy downloadPolicy =
                new BlobEncryptionPolicy(null, keyResolver);
        BlobRequestOptions options = new BlobRequestOptions();
        options.setEncryptionPolicy(downloadPolicy);

        GetKeysResponse.Key ionicKey = keyResolver.getKey();
        assertNull(ionicKey);
    }


    /*
     * test07_DownloadBlob() - Download and decrypt blob using KeyResolver to obtain IKey
     * pre-req: Upload blob to Azure Cloud Storage
     */
    @Test
    public void test07_DownloadBlob() throws IonicException, URISyntaxException, StorageException, IOException {
        // Note: Container name must be lower case.
        CloudBlobContainer container = mCloudBlobClient.getContainerReference(mContainerName);
        container.createIfNotExists();

        // Download an string.
        CloudBlockBlob blob = container.getBlockBlobReference(mBlobName);

        // Download the encrypted blob.
        // For downloads, a resolver can be set up that will help pick the
        // key based on the key id.
        // Create the encryption policy to be used for download.
        //    create with IKeyResolver
        KeyResolver keyResolver = mAzureIonicStorage.getKeyResolver();
        BlobEncryptionPolicy downloadPolicy =
                new BlobEncryptionPolicy(null, keyResolver);

        // Set the encryption policy on the request options.
        BlobRequestOptions options = new BlobRequestOptions();
        options.setEncryptionPolicy(downloadPolicy);

        // Download and decrypt the encrypted contents from the blob.
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, options, null);

        assertTrue(byteArrayOutputStream.toString().equals(mOriginalBlobContent));
    }
    
    /*
     * test08_GetResolveKeyAfterDownload() - Verify ability to get IKey from
     *                                       KeyResolver after successful download using KeyResolver
     */
    @Test
    public void test08_GetResolveKeyAfterDownload() throws Exception {
        // Note: Container name must be lower case.
        CloudBlobContainer container = mCloudBlobClient.getContainerReference(mContainerName);
        container.createIfNotExists();

        // Download an string.
        CloudBlockBlob blob = container.getBlockBlobReference(mBlobName);

        // Download the encrypted blob.
        // For downloads, a resolver can be set up that will help pick the
        // key based on the key id.
        // Create the encryption policy to be used for download.
        //    create with IKeyResolver
        KeyResolver keyResolver = mAzureIonicStorage.getKeyResolver();
        BlobEncryptionPolicy downloadPolicy =
                new BlobEncryptionPolicy(null, keyResolver);

        // Set the encryption policy on the request options.
        BlobRequestOptions options = new BlobRequestOptions();
        options.setEncryptionPolicy(downloadPolicy);

        // Download and decrypt the encrypted contents from the blob.
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        blob.download(byteArrayOutputStream, null, options, null);
      
        GetKeysResponse.Key ionicKey = keyResolver.getKey();
        assertNotNull(ionicKey);
    }

    /*
     * test09_KeyAttributesMap() - Verify ability to Set and Get default key attributes
     *                             map from AzureIonicStorage
     */
    @Test
    public void test09_KeyAttributesMap() throws Exception {
        // Get empty KeyAttributesMap
        KeyAttributesMap testAttributes = mAzureIonicStorage.getKeyAttributes();
        assertTrue(testAttributes.isEmpty());
        
        // Set default KeyAttributesMap
        mAzureIonicStorage.setKeyAttributes(mBaseKeyAttributesMap);
        // Get default KeyAttributesMap
        testAttributes = mAzureIonicStorage.getKeyAttributes();

        // Verify entrySets have same size and every member in one Set is contained in the other
        assertTrue(testAttributes.entrySet().equals(mBaseKeyAttributesMap.entrySet()));
    }

    /*
     * test10_MetadataMap() - Verify ability to Set and Get MetadataMap
     *                        from AzureIonicStorage
     */
    @Test
    public void test10_MetadataMap() throws Exception {
        MetadataMap testMetadataMap = mAzureIonicStorage.getIonicMetadataMap();
        assertTrue(testMetadataMap.isEmpty());

        MetadataMap baseMetadata = new MetadataMap();
        baseMetadata.set("metaKey001", "metaValue001");
        baseMetadata.set("metaKey002", "metaValue002");

        mAzureIonicStorage.setIonicMetadataMap(baseMetadata);
        
        testMetadataMap = mAzureIonicStorage.getIonicMetadataMap();

        // Verify entrySets have same size and every member in one Set is contained in the other
        assertTrue(testMetadataMap.entrySet().equals(baseMetadata.entrySet()));
    }

}
