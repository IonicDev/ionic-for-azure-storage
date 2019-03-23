/*
 * IonicAzureStorageSampleApp.java The purpose of this project is to store an object in Azure Blob
 * Storage with client-side Ionic protection. This code is an example of what clients would use
 * programmatically to incorporate the Ionic platform into their Azure use cases.
 *
 * (c) 2019 Ionic Security Inc. By using this code, I agree to the LICENSE included, as well as
 * the Terms & Conditions (https://dev.ionic.com/use) and the Privacy Policy
 * (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.samples;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringBufferInputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.StorageException;
import com.ionic.sdk.agent.data.MetadataMap;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.agent.request.getkey.GetKeysResponse;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.IonicException;
import com.ionic.cloudstorage.azurestorage.AzureIonicStorage;
import com.ionic.cloudstorage.azurestorage.Version;


public class IonicAzureStorageSampleApp {

    enum Action {
        GETSTRING("getString"),
        GETFILE("getFile"),
        PUTSTRING("putString"),
        PUTFILE("putFile"),
        VERSION("version"),;

        final String str;

        Action(String name) {
            this.str = name;
        }
    }

    public static final boolean useSandbox = false; // if true limit file paths to within user's
                                                    // home dir
    private static final String HOME = System.getProperty("user.home");

    private static String mAccountName;
    private static String mAccountKey;
    private static String mStorageConnectionString;

    static void doBlobUpload(InputStream inputStream, long streamLength, String containerName,
            String blobName, CloudBlobClient serviceClient, AzureIonicStorage aiStorage,
            KeyAttributesMap attributes) {

        try {
            // Note: Container name must be lower case.
            CloudBlobContainer container = serviceClient.getContainerReference(containerName);
            container.createIfNotExists();

            // Upload a string.
            CloudBlockBlob blob = container.getBlockBlobReference(blobName);

            // Create the IKey used for encryption.
            SymmetricKey key;

            if (attributes != null) {
                key = aiStorage.create(new CreateKeysRequest.Key("", 1, attributes));
            } else {
                key = aiStorage.create();
            }

            // Create the encryption policy to be used for upload.
            BlobEncryptionPolicy policy = new BlobEncryptionPolicy(key, null);

            // Set the encryption policy on the request options.
            BlobRequestOptions options = new BlobRequestOptions();
            options.setEncryptionPolicy(policy);

            if (blob.exists()) {
                // Download pre-existing Metadata to retain when uploading new attributes
                blob.downloadAttributes();
            }

            // Upload the encrypted contents to the blob.
            blob.upload(inputStream, streamLength, null, options, null);

        } catch (IOException e) {
            System.err.println("IOException");
            return;
        } catch (StorageException storageException) {
            System.err.print("StorageException encountered: ");
            System.err.println(storageException.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.print("Exception encountered: ");
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }

    static void doBlobDownload(String containerName, String blobName, CloudBlobClient serviceClient,
            AzureIonicStorage aiStorage, File downloadTargetFile) {

        OutputStream fileOutputStream = null;

        try {
            // Note: Container name must be lower case.
            CloudBlobContainer container = serviceClient.getContainerReference(containerName);
            container.createIfNotExists();

            // Download an string.
            CloudBlockBlob blob = container.getBlockBlobReference(blobName);

            // Download the encrypted blob.
            // For downloads, a resolver can be set up that will help pick the
            // key based on the key id.
            // Create the encryption policy to be used for download.
            AzureIonicStorage.KeyResolver keyResolver = aiStorage.getKeyResolver();
            BlobEncryptionPolicy downloadPolicy =
                    new BlobEncryptionPolicy(null, keyResolver);

            // Set the encryption policy on the request options.
            BlobRequestOptions options = new BlobRequestOptions();
            options.setEncryptionPolicy(downloadPolicy);

            // Download the MetaData so you can get it with the HashMap Iterator
            blob.downloadAttributes();

            // Display the downloaded attributes
            System.out.println("Display Blob Metadata:");
            HashMap<String, String> metadata = blob.getMetadata();
            Iterator it = metadata.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry pair = (Map.Entry) it.next();
                System.out.printf("    %s = %s%n", pair.getKey(), pair.getValue());
                it.remove();
            }

            // Download and decrypt the encrypted contents from the blob.
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            blob.download(byteArrayOutputStream, null, options, null);

            GetKeysResponse.Key ionicKey = keyResolver.getKey();
            // Display the ionic key attributes
            System.out.println("Display Ionic Key Attributes:");
            printMap(ionicKey.getAttributesMap());

            if (downloadTargetFile == null) {
                // print string to stdout
                System.out.println("Display Blob as string:");
                System.out.println(byteArrayOutputStream);
            } else {
                // Write file to destination file
                System.out.println("Stream Blob to target file");
                fileOutputStream = new FileOutputStream(downloadTargetFile);
                byteArrayOutputStream.writeTo(fileOutputStream);
            }

        } catch (StorageException storageException) {
            System.err.print("StorageException encountered: ");
            System.err.println(storageException.getMessage());
            System.exit(-1);
        } catch (Exception e) {
            System.err.print("Exception encountered: ");
            System.err.println(e.getMessage());
            System.exit(-1);
        } finally {
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.close();
                } catch (IOException e) {
                    System.err.println("IOException encountered: ");
                    System.err.println(e.getMessage());
                    System.exit(-1);
                }
            }
        }
    }


    public static void printMap(KeyAttributesMap map) {
        map.forEach((k, v) -> {
            System.out.print("    ");
            System.out.print((k));
            v.forEach((i) -> System.out.print(":" + i));
            System.out.println("");
        });
    }


    static void putString(String containerName, String blobName, String objectContent,
            CloudBlobClient serviceClient, AzureIonicStorage aiStorage,
            KeyAttributesMap attributes) {

        doBlobUpload(new StringBufferInputStream(objectContent), objectContent.length(),
                containerName, blobName, serviceClient, aiStorage, attributes);
    }

    static void getString(String containerName, String blobName, CloudBlobClient serviceClient,
            AzureIonicStorage aiStorage) {

        doBlobDownload(containerName, blobName, serviceClient, aiStorage, null);
    }

    static void putFile(String containerName, String blobName, String filePath,
            CloudBlobClient serviceClient, AzureIonicStorage aiStorage,
            KeyAttributesMap attributes) {

        String srcFilePathStr = getCanonicalPathString(filePath);

        if ((srcFilePathStr == null) || (srcFilePathStr.isEmpty())) {
            System.err.println("No filepath specified");
            return;
        }

        // Sandbox within user home
        if ((useSandbox) && (!srcFilePathStr.startsWith(HOME))) {
            System.err.println("Filepath outside of user home");
            return;
        }

        Path srcFilePath = Paths.get(srcFilePathStr);

        if (!Files.exists(srcFilePath)) {
            System.err.println("File " + srcFilePathStr + " does not exist.");
            return;
        }
        if (!Files.isRegularFile(srcFilePath)) {
            System.err.println("File " + srcFilePathStr + " not a file.");
            return;
        }

        // Write the Blob and put it in Azure Storage:
        File sourceFile = srcFilePath.toFile();

        if (sourceFile.exists() && sourceFile.isFile()) {
            try {
                doBlobUpload(new FileInputStream(sourceFile), sourceFile.length(), containerName,
                        blobName, serviceClient, aiStorage, attributes);
            } catch (FileNotFoundException e) {
                System.err.println("File " + srcFilePathStr + " not found.");
            }
        }
    }

    static void getFile(String containerName, String blobName, String destination,
            CloudBlobClient serviceClient, AzureIonicStorage aiStorage) {

        System.out.println("Getting object as file from container");

        String destFilePathStr = getCanonicalPathString(destination);

        if ((destFilePathStr == null) || (destFilePathStr.isEmpty())) {
            System.err.println("No filepath specified");
            return;
        }

        Path destFilePath = null;

        // Sandbox within user home
        if ((useSandbox) && (!destFilePathStr.startsWith(HOME))) {
            System.err.println("Filepath outside of user home");
            return;
        }

        destFilePath = Paths.get(destFilePathStr);

        // Check if file already exists but is not a file (e.g. don't try to overwrite a directory)
        if ((Files.exists(destFilePath)) && (!Files.isRegularFile(destFilePath))) {
            System.err.println("File " + destFilePathStr + " not a file.");
            return;
        }

        try {
            // Safe to delete existing file
            Files.deleteIfExists(destFilePath);
        } catch (IOException e) {
            System.err.println("IOException delete destination: " + destFilePathStr);
            return;
        }

        doBlobDownload(containerName, blobName, serviceClient, aiStorage, destFilePath.toFile());
    }

    private static CloudBlobClient initializeCloudBlobClient(String storageConnectionString) {
        try {
            CloudStorageAccount account = CloudStorageAccount.parse(storageConnectionString);
            CloudBlobClient serviceClient = account.createCloudBlobClient();
            return serviceClient;
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
        return null;
    }

    private static AzureIonicStorage initializeAzureIonicStorage()
            throws IOException, IonicException {
        // Load a plain-text device profile (SEP) from disk
        DeviceProfilePersistorPlainText ptPersistor = new DeviceProfilePersistorPlainText();

        String sProfilePath =
                Paths.get(HOME + "/.ionicsecurity/profiles.pt").toFile().getCanonicalPath();
        ptPersistor.setFilePath(sProfilePath);

        AzureIonicStorage ionicStorage = new AzureIonicStorage(ptPersistor);

        ionicStorage.setIonicMetadataMap(getMetadataMap());

        return ionicStorage;
    }


    public static void main(String[] args) throws IOException {

        try {
            // Retrieve and Initialize Azure Shared Key Credentials
            // Account Name - AZURE_STORAGE_ACCOUNT
            // Account Key - AZURE_STORAGE_ACCESS_KEY
            // Obtained from https://portal.azure.com/#home
            // Select Storage Accounts
            // Select Your Storage Account
            // Select Access Keys
            // Copy the Account Name and the Key string from selected active key
            // export to env
            // export AZURE_STORAGE_ACCOUNT=<nameofstorageaccount>
            // export AZURE_STORAGE_ACCESS_KEY=<keystringofactivekeyselected>
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

        Action action = null;
        boolean mFlag = false;
        int actionArg = 0;
        int containerNameArg = 1;
        int objectKeyArg = 2;
        int minimumArgs = 3; // minimum number of args for actions
        int objectContentArg = 3;
        int filePathArg = 3;
        int captureMetadataArg = 4;
        int attributesArg = 4;

        String filePath = null;
        KeyAttributesMap attributes = null;

        // Command Line Processing
        if (args.length <= actionArg) {
            usage();
            return;
        }

        // Determine Action (e.g. getString)
        for (Action a : Action.values()) {
            if (a.str.equals(args[actionArg])) {
                action = a;
                break;
            }
        }
        if (action == null) {
            usage();
            return;
        } else if (action == Action.VERSION) {
            System.out.println(Version.getFullVersion());
            return;
        }

        // Test for minimum args
        if (args.length < minimumArgs) {
            usage();
            return;
        }

        // Get containerName arg
        String containerName = new String(args[1]);
        // Note: IonicAzureStorageSampleApp does not protect against invalid entry of Azure
        // container names. See current Rules for naming Azure containers.

        // Get Object Key arg
        String blobName = new String(args[2]);
        // Note: IonicAzureStorageSampleApp does not protect against invalid entry of Azure blob
        // names. See current rules for specifying Azure Blob names.

        CloudBlobClient serviceClient;
        serviceClient = initializeCloudBlobClient(mStorageConnectionString);

        serviceClient.getDefaultRequestOptions().setRequireEncryption(true);

        AzureIonicStorage aiStorage;

        try {
            aiStorage = initializeAzureIonicStorage();
        } catch (IonicException e) {
            System.err.println("Can't get agent: " + e.getMessage());
            return;
        }

        switch (action) {
            case PUTFILE:

                if (args.length > filePathArg) {
                    String srcFilePath =
                            Paths.get(new String(args[filePathArg])).toFile().getCanonicalPath();

                    // Optional: parse any attributes
                    if (args.length > attributesArg) {
                        attributes = parseAttributes(args[attributesArg]);
                        if (attributes == null) {
                            return;
                        }
                    }

                    putFile(containerName, blobName, srcFilePath, serviceClient, aiStorage,
                            attributes);
                } else {
                    usage();
                }
                break;

            case PUTSTRING:
                if (args.length > objectContentArg) {
                    String objectContent = new String(args[objectContentArg]);

                    // Optional: parse any attributes
                    if (args.length > attributesArg) {
                        attributes = parseAttributes(args[attributesArg]);
                        if (attributes == null) {
                            return;
                        }
                    }

                    putString(containerName, blobName, objectContent, serviceClient, aiStorage,
                            attributes);
                } else {
                    usage();
                }

                break;

            case GETSTRING:

                getString(containerName, blobName, serviceClient, aiStorage);

                break;

            case GETFILE:
                if (args.length > filePathArg) {
                    String destFilePath =
                            Paths.get(new String(args[filePathArg])).toFile().getCanonicalPath();

                    getFile(containerName, blobName, destFilePath, serviceClient, aiStorage);
                } else {
                    usage();
                }

                break;

            case VERSION:
                System.out.println(Version.getFullVersion());
                break;

            default:
                usage();
                break;
        }
    }

    public static KeyAttributesMap parseAttributes(String str) {
        KeyAttributesMap ret = new KeyAttributesMap();
        String[] pairs = str.split(",");
        for (String pair : pairs) {
            String[] tuples = pair.split(":");
            ArrayList<String> values = new ArrayList<String>();
            for (int i = 1; i < tuples.length; i++) {
                values.add(tuples[i]);
            }
            ret.put(tuples[0], values);
        }
        return ret;
    }

    public static MetadataMap getMetadataMap() {
        MetadataMap mApplicationMetadata = new MetadataMap();
        mApplicationMetadata.set("ionic-application-name", "IonicAzureStorageExample");
        mApplicationMetadata.set("ionic-application-version", Version.getFullVersion());
        mApplicationMetadata.set("ionic-client-type", "Cloud Connector");
        mApplicationMetadata.set("ionic-client-version", Version.getFullVersion());

        return mApplicationMetadata;
    }

    public static String getCanonicalPathString(String originalPath) {
        String canonicalPathStr = null;

        try {
            canonicalPathStr = Paths.get(originalPath).toFile().getCanonicalPath();
        } catch (NullPointerException e) {
            System.err.println("Missing original pathname");
        } catch (IOException e) {
            System.err.println("Path IOError");
        }
        return canonicalPathStr;
    }

    private static void usage() {
        System.out.println("Usage: prog <put<x> command> | <get<x> command> | version");
        System.out.println("put<x> commands:");
        System.out.println(
                "\tNOTE: <attributes> for these commands is a comma delimited list of key:value1,value2... ");
        System.out.println(
                "\t\tEx: \"attribute1:val1:val2,attribute2:val3\" -> [attribute1:val1,val2],[attribute2:val3]");
        System.out.println("");
        System.out.println("\tputFile <containerName> <blobName> <fileSourcePath> [<attributes>]");
        System.out.println("\tputString <containerName> <blobName> <contentString> [<attributes>]");
        System.out.println("get<x> commands:");
        System.out.println("\tgetFile <containerName> <blobName> <destinationPath");
        System.out.println("\tgetString <containerName> <blobName>");
    }

}
