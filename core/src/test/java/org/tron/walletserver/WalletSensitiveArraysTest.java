package org.tron.walletserver;

import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.SensitiveData;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.Assert.*;

public class WalletSensitiveArraysTest {
    private static final String PHRASE = "abandon abandon abandon abandon abandon abandon "
            + "abandon abandon abandon abandon abandon about";

    @Test
    public void settersAndCopiesHaveIndependentOwnershipAndReplacementWipesOldStorage()
            throws Exception {
        Wallet wallet = new Wallet();
        char[] input = PHRASE.toCharArray();
        wallet.setMnemonicChars(input);
        char[] stored = ownedPhrase(wallet);
        char[] exported = wallet.copyMnemonicChars();
        assertNotSame(input, stored);
        assertNotSame(stored, exported);
        input[0] = 'x';
        exported[1] = 'x';
        assertEquals(PHRASE, wallet.getMnemonic());
        wallet.setMnemonicChars(new char[]{'n', 'e', 'w'});
        assertArrayEquals(new char[stored.length], stored);
        assertArrayEquals(new char[]{'n', 'e', 'w'}, wallet.copyMnemonicChars());
        SensitiveData.clear(input);
        SensitiveData.clear(exported);
        wallet.clearSensitiveData();
    }

    @Test
    public void clearWipesActualOwnedBuffersButDoesNotEraseCallerCopies() throws Exception {
        Wallet wallet = Wallet.fromMnemonicChars(PHRASE.toCharArray(), WalletPath.createDefault());
        String address = wallet.getAddress();
        byte[] publicKey = wallet.getPublicKey();
        char[] owned = ownedPhrase(wallet);
        char[] callerCopy = wallet.copyMnemonicChars();
        byte[] legacyKeyAlias = wallet.getPrivateKeyBytes33();
        wallet.clearSensitiveData();
        wallet.clearSensitiveData();
        assertArrayEquals(new char[owned.length], owned);
        assertArrayEquals(new byte[legacyKeyAlias.length], legacyKeyAlias);
        assertArrayEquals(PHRASE.toCharArray(), callerCopy);
        assertNull(wallet.copyMnemonicChars());
        assertNull(wallet.getMnemonic());
        assertNull(wallet.getPrivateKey());
        assertNull(wallet.getECKey());
        assertFalse(wallet.isOpen());
        assertEquals(address, wallet.getAddress());
        assertArrayEquals(publicKey, wallet.getPublicKey());
        SensitiveData.clear(callerCopy);
    }

    @Test
    public void bytePrivateKeyFactoryBorrowsInputAndPreservesLegacyWidth() {
        byte[] input = new byte[32];
        input[31] = 1;
        Wallet wallet = Wallet.fromPrivateKeyBytes(input);
        assertTrue(wallet.isOpen());
        assertArrayEquals(input, wallet.getPrivateKey());
        assertEquals(32, wallet.getPrivateKeyBytes33().length);
        Arrays.fill(input, (byte) 0);
        assertEquals(1, wallet.getPrivateKey()[31]);
        byte[] digest = new byte[32];
        assertTrue(wallet.getECKey().verify(digest, wallet.getECKey().doSign(digest)));
        wallet.clearSensitiveData();
        assertFalse(Wallet.fromPrivateKeyBytes(input).isOpen());
        assertFalse(Wallet.fromPrivateKeyBytes(new byte[31]).isOpen());
        assertFalse(Wallet.fromPrivateKeyBytes(null).isOpen());
    }

    @Test
    public void hexFactoryPreservesPrefixCaseLeadingZerosAndClosedFailures() {
        String key = "00000000000000000000000000000000000000000000000000000000000000AB";
        char[] input = ("0X" + key).toCharArray();
        Wallet wallet = Wallet.fromPrivateKeyChars(input);
        Wallet legacy = new Wallet(I_TYPE.PRIVATE, key);
        assertTrue(wallet.isOpen());
        assertArrayEquals(legacy.getPrivateKey(), wallet.getPrivateKey());
        assertArrayEquals(("0X" + key).toCharArray(), input);
        for (String invalid : new String[]{"", "1", "  " + key, key + "0",
                key.substring(0, 63) + "g", key.replace('A', '\uff21'),
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"}) {
            Wallet rejected = Wallet.fromPrivateKeyChars(invalid.toCharArray());
            assertFalse(rejected.isOpen());
            assertNull(rejected.getPrivateKeyBytes33());
        }
        assertFalse(Wallet.fromPrivateKeyChars(null).isOpen());
        wallet.clearSensitiveData();
        legacy.clearSensitiveData();
        SensitiveData.clear(input);
    }

    @Test
    public void mnemonicFactoriesPreserveStrictLegacyAndRetentionRules() {
        char[] input = PHRASE.toCharArray();
        Wallet strict = Wallet.fromMnemonicStrictChars(input);
        assertTrue(strict.isOpen());
        assertNull(strict.copyMnemonicChars());
        Wallet custom = Wallet.fromMnemonicChars(input, WalletPath.createDefault());
        assertArrayEquals(strict.getPrivateKey(), custom.getPrivateKey());
        assertEquals(33, custom.getPrivateKeyBytes33().length);
        assertArrayEquals(input, custom.copyMnemonicChars());
        char[] trailing = (PHRASE + " ").toCharArray();
        Wallet legacy = Wallet.fromMnemonicChars(trailing);
        assertTrue(legacy.isOpen());
        assertFalse(Arrays.equals(strict.getPrivateKey(), legacy.getPrivateKey()));
        assertFalse(Wallet.fromMnemonicStrictChars(trailing).isOpen());
        assertFalse(Wallet.fromMnemonicChars(" null ".toCharArray(), WalletPath.createDefault()).isOpen());
        assertArrayEquals(PHRASE.toCharArray(), input);
        for (Wallet wallet : new Wallet[]{strict, custom, legacy}) wallet.clearSensitiveData();
        SensitiveData.clear(input);
        SensitiveData.clear(trailing);
    }

    @Test
    public void concurrentCopyNeverSeesPartiallyClearedOrReplacedPhrase() throws Exception {
        Wallet wallet = new Wallet();
        char[] a = new char[128];
        char[] b = new char[128];
        Arrays.fill(a, 'a');
        Arrays.fill(b, 'b');
        wallet.setMnemonicChars(a);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> writer = executor.submit(() -> {
                await(start);
                for (int i = 0; i < 1000; i++) {
                    wallet.setMnemonicChars((i & 1) == 0 ? a : b);
                    if (i % 3 == 0) wallet.clearSensitiveData();
                }
            });
            Future<?> reader = executor.submit(() -> {
                await(start);
                for (int i = 0; i < 1000; i++) {
                    char[] copy = wallet.copyMnemonicChars();
                    if (copy != null) {
                        assertEquals(128, copy.length);
                        assertTrue(copy[0] == 'a' || copy[0] == 'b');
                        for (char c : copy) assertEquals(copy[0], c);
                        SensitiveData.clear(copy);
                    }
                }
            });
            start.countDown();
            writer.get();
            reader.get();
        } finally {
            executor.shutdownNow();
            wallet.clearSensitiveData();
            SensitiveData.clear(a);
            SensitiveData.clear(b);
        }
    }

    private static char[] ownedPhrase(Wallet wallet) throws Exception {
        Field field = Wallet.class.getDeclaredField("mnemonicChars");
        field.setAccessible(true);
        return (char[]) field.get(wallet);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
