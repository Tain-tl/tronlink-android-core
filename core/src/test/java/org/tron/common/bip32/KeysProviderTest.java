package org.tron.common.bip32;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeysProviderTest {
    @Test
    public void initializationOrdersPreserveKeyGenerationAndTronHashing() throws Exception {
        // Isolate static initializers from both earlier tests and each other.
        List<URL> classpath = new ArrayList<>();
        // Locate the crypto runtime without depending on Gradle's classloader implementation.
        for (Class<?> dependency : new Class<?>[]{Keys.class, BouncyCastleProvider.class,
                org.slf4j.LoggerFactory.class, com.google.common.base.Preconditions.class}) {
            classpath.add(dependency.getProtectionDomain().getCodeSource().getLocation());
        }
        Provider original = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        List<Provider> providers = java.util.Arrays.asList(Security.getProviders());
        int originalPosition = providers.indexOf(original) + 1;
        try {
            for (String order : new String[]{"KEH", "KHE", "EKH", "EHK", "HKE", "HEK"}) {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
                try (URLClassLoader loader = new URLClassLoader(classpath.toArray(new URL[0]),
                        ClassLoader.getSystemClassLoader().getParent())) {
                    Class<?> keys = loader.loadClass("org.tron.common.bip32.Keys");
                    Class<?> ecKey = loader.loadClass("org.tron.common.crypto.ECKey");
                    Class<?> hash = loader.loadClass("org.tron.common.crypto.Hash");
                    for (char step : order.toCharArray()) {
                        if (step == 'K') {
                            keys.getMethod("createEcKeyPair").invoke(null);
                        } else if (step == 'E') {
                            ecKey.getConstructor().newInstance();
                        } else {
                            byte[] digest = (byte[]) hash.getMethod("sha3", byte[].class)
                                    .invoke(null, (Object) new byte[1]);
                            assertEquals(order, 32, digest.length);
                        }
                    }
                    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
                    keys.getMethod("createEcKeyPair").invoke(null);
                }
            }
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (original != null) {
                Security.insertProviderAt(original, originalPosition);
            }
        }
    }

    @Test
    public void concurrentKeyGenerationProducesValidDistinctKeys() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Future<ECKeyPair>> results = new ArrayList<>();
            for (int i = 0; i < 32; i++) {
                results.add(executor.submit(Keys::createEcKeyPair));
            }
            Set<BigInteger> publicKeys = new HashSet<>();
            for (Future<ECKeyPair> result : results) {
                ECKeyPair key = result.get(30, TimeUnit.SECONDS);
                assertTrue(key.getPrivateKey().signum() > 0);
                assertTrue(key.getPrivateKey().compareTo(Sign.CURVE.getN()) < 0);
                assertEquals(Sign.publicKeyFromPrivate(key.getPrivateKey()), key.getPublicKey());
                assertTrue(publicKeys.add(key.getPublicKey()));
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void createsKeysAfterGlobalProviderIsRemoved() throws Exception {
        Provider original = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        int originalPosition = -1;
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            if (providers[i] == original) {
                originalPosition = i + 1;
                break;
            }
        }
        try {
            Keys.createEcKeyPair();
            // Reproduce TronCastleProvider's removal even if another test initialized it.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            ECKeyPair key = Keys.createEcKeyPair();
            assertTrue(key.getPrivateKey().signum() > 0);
            assertTrue(key.getPrivateKey().compareTo(Sign.CURVE.getN()) < 0);
            assertEquals(Sign.publicKeyFromPrivate(key.getPrivateKey()), key.getPublicKey());
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (original != null) {
                Security.insertProviderAt(original, originalPosition);
            }
        }
    }
}
