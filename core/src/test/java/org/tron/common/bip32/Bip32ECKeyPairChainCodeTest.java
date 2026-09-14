package org.tron.common.bip32;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class Bip32ECKeyPairChainCodeTest {
    private static Bip32ECKeyPair masterKey() {
        // Public BIP-32 test vector seed, never a production key.
        return Bip32ECKeyPair.generateKeyPair(
                Numeric.hexStringToByteArray("000102030405060708090a0b0c0d0e0f"));
    }

    @Test
    public void modifyingReturnedChainCodeDoesNotChangeDerivation() {
        Bip32ECKeyPair master = masterKey();
        byte[] expectedChainCode = master.getChainCode().clone();
        int[][] paths = {{Bip32ECKeyPair.HARDENED_BIT}, {1}};
        Bip32ECKeyPair[] expected = new Bip32ECKeyPair[paths.length];
        for (int i = 0; i < paths.length; i++) {
            expected[i] = Bip32ECKeyPair.deriveKeyPair(master, paths[i]);
        }

        Arrays.fill(master.getChainCode(), (byte) 0);

        for (int i = 0; i < paths.length; i++) {
            Bip32ECKeyPair actual = Bip32ECKeyPair.deriveKeyPair(master, paths[i]);
            assertEquals(expected[i].getPrivateKey(), actual.getPrivateKey());
            assertEquals(expected[i].getPublicKey(), actual.getPublicKey());
            assertArrayEquals(expected[i].getChainCode(), actual.getChainCode());
        }
        assertArrayEquals(expectedChainCode, master.getChainCode());
    }

    @Test
    public void modifyingConstructorInputDoesNotChangeDerivation() {
        Bip32ECKeyPair original = masterKey();
        byte[] input = original.getChainCode();
        Bip32ECKeyPair copy = Bip32ECKeyPair.create(original.getPrivateKey(), input);
        int[] path = {Bip32ECKeyPair.HARDENED_BIT, 1};
        Bip32ECKeyPair expected = Bip32ECKeyPair.deriveKeyPair(copy, path);

        Arrays.fill(input, (byte) 0);

        Bip32ECKeyPair actual = Bip32ECKeyPair.deriveKeyPair(copy, path);
        assertEquals(expected.getPrivateKey(), actual.getPrivateKey());
        assertArrayEquals(expected.getChainCode(), actual.getChainCode());
    }
}
