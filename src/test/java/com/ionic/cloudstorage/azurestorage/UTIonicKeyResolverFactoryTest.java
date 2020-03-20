/*
 * (c) 2019-2020 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.azurestorage;

import static org.junit.Assert.*;

import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.data.MetadataMap;
import com.ionic.sdk.agent.key.AgentKey;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.IonicException;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import java.util.ArrayList;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.Test;

public class UTIonicKeyResolverFactoryTest {

    private byte[] keyBytes = new byte[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void constructorWithAgent() throws IonicException {
        Agent agent = new Agent();

        new IonicKeyResolverFactory(agent);
    }

    @Test
    public void setGetDefaultKeyAttributes() {
        IonicKeyResolverFactory storage = new IonicKeyResolverFactory();

        assertTrue("KeyAttributes were not empty by default.",
            storage.getDefaultKeyAttributes().isEmpty());

        KeyAttributesMap kam = new KeyAttributesMap();
        ArrayList<String> collection = new ArrayList<String>();
        collection.add("confidential");
        collection.add("secured");
        kam.put("privacy", collection);

        storage.setDefaultKeyAttributes(kam);
        assertEquals("getKeyAttributes() did not equal map set with setDefaultAttributes()",
            storage.getDefaultKeyAttributes(), kam);
    }

    @Test
    public void ionicKeyToSymmetricKey() throws NullPointerException {
        AgentKey ionicKey = new AgentKey("1234", keyBytes);

        SymmetricKey symmetricKey = IonicKeyResolverFactory.ionicKeyToSymmetricKey(ionicKey);
        // Should check that symmetricKey.keyBytes == keyBytes, but no getters exposed
    }

    @Test
    public void createKeyResolver() {
        IonicKeyResolverFactory storage = new IonicKeyResolverFactory();
        IonicKeyResolverFactory.IonicKeyResolver resolver = storage.createKeyResolver();
    }
}
