/*
 * (c) 2019-2020 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import com.ionic.sdk.agent.Agent;
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
import java.util.Arrays;


public class IonicKeyResolverFactory {

    private Agent agent = new Agent();
    private KeyAttributesMap attributes = new KeyAttributesMap();

    public IonicKeyResolverFactory() {}

    public IonicKeyResolverFactory(Agent agent) {
        setAgent(agent);
    }

    /**
     * Sets the Ionic Agent object backing the IonicKeyResolverFactory instance.
     *
     * @param agent an {@link com.ionic.sdk.agent.Agent} object.
     */
    public void setAgent(Agent agent) {
        this.agent = agent;
    }

    /**
     * Returns the Agent object backing the IonicKeyResolverFactory instance.
     *
     * @return a {@link com.ionic.sdk.agent.Agent}
     */
    public Agent getAgent() {
        return this.agent;
    }

    /**
     * Sets the default Attributes to be applied to all Agent.keyCreate() requests.
     *
     * @param attributes a {@link com.ionic.sdk.agent.key.KeyAttributesMap} object.
     */
    public void setDefaultKeyAttributes(KeyAttributesMap attributes) {
        this.attributes = new KeyAttributesMap(attributes);
    }

    /**
     * Gets the default Attributes which are applied to all Agent.keyCreate() requests.
     *
     * @return a {@link com.ionic.sdk.agent.key.KeyAttributesMap} object.
     */
    public KeyAttributesMap getDefaultKeyAttributes() {
        return new KeyAttributesMap(this.attributes);
    }

    /**
     * Returns a SymmetricKey representation of a newly created Ionic Key using the default
     * {@link com.ionic.sdk.agent.key.KeyAttributesMap} set on IonicKeyResolverFactory
     * (empty by default).
     *
     * @return a {@link com.microsoft.azure.keyvault.cryptography.SymmetricKey}
     */
    public SymmetricKey create() throws IonicException {
        return create(new CreateKeysRequest.Key(""));
    }

    /**
     * Returns a SymmetricKey representation of a newly created Ionic Key using the default
     * {@link com.ionic.sdk.agent.key.KeyAttributesMap} set on IonicKeyResolverFactory
     * and the Attributes and MutableAttributes specified on the CreateKeysRequest.Key.
     * In the event of a collision betwen the default Attributes and the Attributes from
     * the CreateKeysRequest.Key the CreateKeysRequest.Key Attributes will take precedence.
     *
     * @param key a {@link com.ionic.sdk.agent.request.createkey.CreateKeysRequest}
     * @return a {@link com.microsoft.azure.keyvault.cryptography.SymmetricKey}
     */
    public SymmetricKey create(CreateKeysRequest.Key key) throws IonicException {
        return createIonicKey(key);
    }

    protected SymmetricKey createIonicKey(CreateKeysRequest.Key key) throws IonicException {

        KeyAttributesMap attributesMap = new KeyAttributesMap();

        // Add "Default" attributes set with setKeyAttributes() method
        attributesMap.putAll(attributes);
        // Add attributes passed in with CreateKeysRequest.Key key

        attributesMap.putAll(key.getAttributesMap());

        AgentKey ionicKey = Agent.clone(agent).createKey(attributesMap,
                key.getMutableAttributesMap()).getFirstKey();
        return ionicKeyToSymmetricKey(ionicKey);
    }

    private GetKeysResponse.Key getIonicKey(String keyid) throws IonicException {
        return Agent.clone(agent).getKey(keyid).getFirstKey();
    }

    protected static SymmetricKey ionicKeyToSymmetricKey(AgentKey key) {
        return new SymmetricKey(key.getId(), key.getKey());
    }

    /**
     * An Implemtation of the {@link com.microsoft.azure.keyvault.core.IKeyResolver}
     * interface that resolves an Ionic Key Into a
     * {@link com.microsoft.azure.keyvault.cryptography.SymmetricKey} representation
     * of the associated Ionic Key.
     * If the IonicKeyResolver encounters an {@link com.ionic.sdk.error.IonicException}
     * it will be wrapped in a {@link java.util.concurrent.ExecutionException} which in
     * turn will be wrapped by a {@link com.microsoft.azure.storage.StorageException}.
     * If the StorageException is caught {@link java.lang.Throwable#getCause()} must be
     * used twice to obtain a refrence to the underlying IonicException.
     * Once a key has been resolved the most recently resolved
     * {@link com.ionic.sdk.agent.request.getkey.GetKeysResponse.Key} can be obtained
     * with the {@link #getKey} method.
     */
    public class IonicKeyResolver implements IKeyResolver {
        private GetKeysResponse.Key ionicKey = null;

        /**
         * Returns the {@link com.ionic.sdk.agent.request.getkey.GetKeysResponse.Key}
         * for the last Ionic KeyID resolved or null if no key has been resolved.
         *
         * @return a {@link com.ionic.sdk.agent.request.getkey.GetKeysResponse.Key}
         */
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
                future.setException(e);
            }
            return future;
        }
    }

    /**
     * Returns a new instance of IonicKeyResolver.
     *
     * @return a IonicKeyResolver
     */
    public IonicKeyResolver createKeyResolver() {
        return new IonicKeyResolver();
    }

}
