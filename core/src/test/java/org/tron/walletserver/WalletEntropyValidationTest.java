package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.MnemonicUtils;

import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class WalletEntropyValidationTest {

    @Test
    public void walletCreation_rejectsDegenerateEntropyWithoutRetryAndClearsBuffer() {
        RecordingSecureRandom random = new RecordingSecureRandom(repeatedEntropy((byte) 0x5a));

        assertWalletCreationFailsWithEntropyQualityException(random);

        Assert.assertEquals(1, random.invocationCount);
        Assert.assertNotNull(random.output);
        Assert.assertArrayEquals(new byte[16], random.output);
    }

    @Test
    public void walletCreation_rejectsConsecutiveDuplicateEntropy() {
        byte[] entropy = nonDegenerateEntropy(0x21);
        primePreviousEntropyWithDifferentValue(entropy);
        RecordingSecureRandom firstRandom = new RecordingSecureRandom(entropy);
        RecordingSecureRandom secondRandom = new RecordingSecureRandom(entropy);

        Wallet firstWallet = new Wallet(true, firstRandom);
        assertWalletCreationFailsWithEntropyQualityException(secondRandom);

        Assert.assertTrue(firstWallet.isOpen());
        Assert.assertEquals(1, firstRandom.invocationCount);
        Assert.assertArrayEquals(new byte[16], firstRandom.output);
        Assert.assertEquals(1, secondRandom.invocationCount);
        Assert.assertArrayEquals(new byte[16], secondRandom.output);
    }

    @Test
    public void walletCreation_concurrentDuplicateEntropyAllowsOnlyOneWallet() throws Exception {
        final byte[] entropy = nonDegenerateEntropy(0x42);
        primePreviousEntropyWithDifferentValue(entropy);
        final CyclicBarrier barrier = new CyclicBarrier(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try {
            Callable<Boolean> createWallet = new Callable<Boolean>() {
                @Override
                public Boolean call() {
                    try {
                        return new Wallet(true, new BarrierSecureRandom(entropy, barrier)).isOpen();
                    } catch (IllegalStateException expected) {
                        if (!(expected.getCause()
                                instanceof MnemonicUtils.EntropyQualityException)) {
                            throw expected;
                        }
                        return false;
                    }
                }
            };

            Future<Boolean> first = executor.submit(createWallet);
            Future<Boolean> second = executor.submit(createWallet);
            int successCount = (first.get() ? 1 : 0) + (second.get() ? 1 : 0);

            Assert.assertEquals(1, successCount);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void generatedEntropyQuality_rejectsKnownDegeneratePatterns() {
        assertEntropyQualityRejected(new byte[16]);
        assertEntropyQualityRejected(repeatedEntropy((byte) 0x5a));

        byte[] ascending = new byte[16];
        byte[] descending = new byte[16];
        for (int i = 0; i < ascending.length; i++) {
            ascending[i] = (byte) i;
            descending[i] = (byte) (descending.length - 1 - i);
        }
        assertEntropyQualityRejected(ascending);
        assertEntropyQualityRejected(descending);
    }

    @Test
    public void generatedEntropyQuality_invalidValueDoesNotReplacePreviousFingerprint() {
        byte[] validEntropy = nonDegenerateEntropy(0x53);
        primePreviousEntropyWithDifferentValue(validEntropy);
        MnemonicUtils.validateGeneratedEntropyQuality(validEntropy);

        assertEntropyQualityRejected(new byte[16]);
        assertEntropyQualityRejected(validEntropy);
    }

    @Test
    public void walletCreation_propagatesEntropySourceFailureAsClosedFailure() {
        try {
            new Wallet(true, new FailingSecureRandom());
            Assert.fail("Expected wallet creation to fail");
        } catch (IllegalStateException expected) {
            Assert.assertTrue(expected.getCause() instanceof ProviderException);
        }
    }

    @Test
    public void walletCreation_acceptsNonDegenerateEntropyAndClearsBuffer() {
        byte[] entropy = nonDegenerateEntropy(0x64);
        primePreviousEntropyWithDifferentValue(entropy);
        RecordingSecureRandom random = new RecordingSecureRandom(entropy);

        Wallet wallet = new Wallet(true, random);

        Assert.assertTrue(wallet.isOpen());
        Assert.assertEquals(1, random.invocationCount);
        Assert.assertNotNull(random.output);
        Assert.assertArrayEquals(new byte[16], random.output);
    }

    @Test
    public void generatedEntropyQuality_acceptsDifferentNonDegenerateValuesInBulk() {
        byte[] firstEntropy = nonDegenerateEntropy(0x70);
        primePreviousEntropyWithDifferentValue(firstEntropy);

        for (int i = 0; i < 64; i++) {
            MnemonicUtils.validateGeneratedEntropyQuality(nonDegenerateEntropy(0x70 + i));
        }
    }

    private static void assertWalletCreationFailsWithEntropyQualityException(
            SecureRandom random) {
        try {
            new Wallet(true, random);
            Assert.fail("Expected wallet creation to fail");
        } catch (IllegalStateException expected) {
            Assert.assertTrue(
                    expected.getCause() instanceof MnemonicUtils.EntropyQualityException);
        }
    }

    private static void assertEntropyQualityRejected(byte[] entropy) {
        try {
            MnemonicUtils.validateGeneratedEntropyQuality(entropy);
            Assert.fail("Expected generated entropy to be rejected");
        } catch (MnemonicUtils.EntropyQualityException expected) {
            // Expected.
        }
    }

    private static void primePreviousEntropyWithDifferentValue(byte[] excludedEntropy) {
        byte[] firstCandidate = nonDegenerateEntropy(0x11);
        byte[] secondCandidate = nonDegenerateEntropy(0x12);
        byte[] candidate = Arrays.equals(firstCandidate, excludedEntropy)
                ? secondCandidate : firstCandidate;
        try {
            MnemonicUtils.validateGeneratedEntropyQuality(candidate);
        } catch (MnemonicUtils.EntropyQualityException duplicateOfPrevious) {
            MnemonicUtils.validateGeneratedEntropyQuality(secondCandidate);
        }
    }

    private static byte[] repeatedEntropy(byte value) {
        byte[] entropy = new byte[16];
        Arrays.fill(entropy, value);
        return entropy;
    }

    private static byte[] nonDegenerateEntropy(int marker) {
        return new byte[] {
                (byte) 0x93, (byte) 0x27, (byte) 0xc4, (byte) 0x5d,
                (byte) 0xe1, (byte) 0x08, (byte) 0x7a, (byte) 0xb6,
                (byte) 0x34, (byte) 0xdf, (byte) 0x62, (byte) 0x19,
                (byte) (marker >>> 24), (byte) (marker >>> 16),
                (byte) (marker >>> 8), (byte) marker
        };
    }

    private static class RecordingSecureRandom extends SecureRandom {
        private final byte[] entropy;
        private byte[] output;
        private int invocationCount;

        private RecordingSecureRandom(byte[] entropy) {
            this.entropy = Arrays.copyOf(entropy, entropy.length);
        }

        @Override
        public void nextBytes(byte[] bytes) {
            invocationCount++;
            output = bytes;
            System.arraycopy(entropy, 0, bytes, 0, bytes.length);
        }
    }

    private static final class BarrierSecureRandom extends RecordingSecureRandom {
        private final CyclicBarrier barrier;

        private BarrierSecureRandom(byte[] entropy, CyclicBarrier barrier) {
            super(entropy);
            this.barrier = barrier;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            super.nextBytes(bytes);
            try {
                barrier.await();
            } catch (Exception ex) {
                throw new ProviderException("simulated synchronization failure", ex);
            }
        }
    }

    private static final class FailingSecureRandom extends SecureRandom {
        @Override
        public void nextBytes(byte[] bytes) {
            throw new ProviderException("simulated RNG failure");
        }
    }
}
