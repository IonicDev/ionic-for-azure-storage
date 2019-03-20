/*
 * (c) 2019 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import java.util.Arrays;
import com.ionic.sdk.agent.data.MetadataMap;
import com.ionic.sdk.agent.key.AgentKey;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.agent.request.getkey.GetKeysResponse;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase;
import com.ionic.sdk.error.IonicException;
import com.microsoft.azure.keyvault.core.IKey;
import com.microsoft.azure.keyvault.core.IKeyResolver;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;

public class AzureIonicStorage {

    private IonicAgentFactory agentFactory = new IonicAgentFactory();
    private KeyAttributesMap attributes = new KeyAttributesMap();


    public AzureIonicStorage() {}

    public AzureIonicStorage(DeviceProfilePersistorBase persistor) throws IonicException {
        setPersistor(persistor);
    }

    /**
     * setPersistor() sets the Persistor with which to create Agents in the agentFactory
     *
     * @param persistor a {@link com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase}
     *        object.
     */
    public void setPersistor(DeviceProfilePersistorBase persistor) throws IonicException {
        agentFactory.setActiveProfile(persistor);
    }

    /**
     * setKeyAttributes() sets the default Attributes to be applied to all Agent.keyCreate()
     * requests
     *
     * @param attributes a {@link com.ionic.sdk.agent.key.KeyAttributesMap} object.
     */
    public void setKeyAttributes(KeyAttributesMap attributes) {
        this.attributes = new KeyAttributesMap(attributes);
    }

    /**
     * getKeyAttributes() gets default Attributes which are applied to all Agent.keyCreate()
     * requests
     *
     * @return a {@link com.ionic.sdk.agent.key.KeyAttributesMap} object.
     */
    public KeyAttributesMap getKeyAttributes() {
        return new KeyAttributesMap(this.attributes);
    }

    /**
     * setIonicMetadataMap() sets the MetadataMap for IDC interactions
     *
     * @param map a {@link com.ionic.sdk.agent.data.MetadataMap} object.
     */
    public void setIonicMetadataMap(MetadataMap map) {
        agentFactory.setMetadataMap(map);
    }

    /**
     * getIonicMetadataMap() gets the MetadataMap used for IDC interactions
     *
     * @return a {@link com.ionic.sdk.agent.data.MetadataMap} object.
     */
    public MetadataMap getIonicMetadataMap() {
        return agentFactory.getMetadataMap();
    }


    public SymmetricKey create() throws IonicException {
        return create(new CreateKeysRequest.Key(""));
    }

    public SymmetricKey create(CreateKeysRequest.Key key) throws IonicException {
        return createIonicKey(key);
    }

    /**
     * A container class that holds a pairing of
     * {@link com.ionic.sdk.agent.request.createkey.CreateKeysResponse.Key} and a byte[] returned by
     * readAllBytesAndKey() methods.
     */
    public class IonicKeyBytesPair {
        private GetKeysResponse.Key key;
        private byte[] byteArray;

        private IonicKeyBytesPair(GetKeysResponse.Key key, byte[] byteArray) {
            this.key = key;
            this.byteArray = byteArray;
        }

        /**
         * Returns a GetKeysResponse.Key.
         * 
         * @return a {@link com.ionic.sdk.agent.request.createkey.CreateKeysResponse.Key}
         */
        public GetKeysResponse.Key getKey() {
            return this.key;
        }

        /**
         * Returns a byte[].
         * 
         * @return a byte[]
         */
        public byte[] getByteArray() {
            return Arrays.copyOf(this.byteArray, this.byteArray.length);
        }
    }

    private SymmetricKey createIonicKey(CreateKeysRequest.Key key) throws IonicException {

        KeyAttributesMap attributesMap = new KeyAttributesMap();

        // Add "Default" attributes set with setKeyAttributes() method
        attributesMap.putAll(attributes);
        // Add attributes passed in with CreateKeysRequest.Key key

        attributesMap.putAll(key.getAttributesMap());

        AgentKey ionicKey = agentFactory.getAgent().createKey(attributesMap, key.getMutableAttributesMap()).getFirstKey();
        return ionicKeyToSymmetricKey(ionicKey);
    }

    private GetKeysResponse.Key getIonicKey(String keyid) throws IonicException {
        return agentFactory.getAgent().getKey(keyid).getFirstKey();
    }

    private static SymmetricKey ionicKeyToSymmetricKey(AgentKey key) {
        return new SymmetricKey(key.getId(), key.getKey());
    }

    public class KeyResolver implements IKeyResolver {
        private GetKeysResponse.Key ionicKey;

        public GetKeysResponse.Key getKey() {
            return ionicKey;
        }

        /**
         * Map from a keyID to a key. This will be called when decrypting. The data to decrypt will
         * include the keyID used to encrypt it.
         * 
         * @param keyId The KeyID to map to a key
         */
        @Override
        public ListenableFuture<IKey> resolveKeyAsync(String keyId) {
            SettableFuture<IKey> future = SettableFuture.create();
            try {
                ionicKey = getIonicKey(keyId);
                future.set(ionicKeyToSymmetricKey(ionicKey));
            } catch (IonicException e) {
                System.err.println(e.getLocalizedMessage());
                future.set(null);
            }
            return future;
        }

        /**
         * Add a key to the local resolver.
         * 
         * @param key The key to add to the local resolver.
         */
        public void add(IKey key) {
            // This method is not needed since the key is stored by IDC, so we can leave it as a
            // stub.
        }
    }

    public KeyResolver getKeyResolver() {
        return new KeyResolver();
    }

}
