package org.tron.common.crypto;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.bip32.Numeric;
import org.tron.common.utils.SensitiveData;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;

public class MnemonicUtilsCharsTest {
    private static final String VECTOR_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon about";
    private static final String VECTOR_SEED =
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                    + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    @Test
    public void arrayApisMatchOfficialVector() {
        char[] mnemonic = MnemonicUtils.generateMnemonicChars(new byte[16]);
        Assert.assertArrayEquals(VECTOR_MNEMONIC.toCharArray(), mnemonic);
        Assert.assertArrayEquals(new byte[16], MnemonicUtils.generateEntropyFromChars(mnemonic));
        byte[] seed = MnemonicUtils.generateSeedFromChars(mnemonic, "TREZOR".toCharArray());
        Assert.assertEquals(VECTOR_SEED, Numeric.toHexStringNoPrefix(seed));
    }

    @Test
    public void everySupportedEntropySizeRoundTripsWithoutChangingBorrowedInput() {
        for (int length = 16; length <= 32; length += 4) {
            byte[] entropy = new byte[length];
            for (int i = 0; i < entropy.length; i++) {
                entropy[i] = (byte) (i * 11 + length);
            }
            byte[] expected = entropy.clone();
            char[] mnemonic = MnemonicUtils.generateMnemonicChars(entropy);
            Assert.assertArrayEquals(expected, entropy);
            char[] mnemonicBeforeValidation = mnemonic.clone();
            Assert.assertTrue(MnemonicUtils.validateMnemonicChars(mnemonic));
            Assert.assertTrue(MnemonicUtils.validateMnemonicStrictChars(mnemonic));
            Assert.assertArrayEquals(expected, MnemonicUtils.generateEntropyFromChars(mnemonic));
            Assert.assertArrayEquals(mnemonicBeforeValidation, mnemonic);
        }
    }

    @Test
    public void unicodeAndMalformedInputPreserveThePreviousNfkdSeedAlgorithm() {
        String[][] examples = {{VECTOR_MNEMONIC, "café"}, {VECTOR_MNEMONIC, "cafe\u0301"},
                {"café mnemonic", "ﬁsh"}, {"cafe\u0301 mnemonic", "fish"},
                {"\u3000钱包\uD83D\uDE00", "\uFF21\u0301"},
                {"a\uD800b", "\uDC00"}};
        for (String[] example : examples) {
            char[] mnemonic = example[0].toCharArray();
            char[] passphrase = example[1].toCharArray();
            Assert.assertArrayEquals(legacySeed(example[0], example[1]),
                    MnemonicUtils.generateSeedFromChars(mnemonic, passphrase));
            Assert.assertArrayEquals(example[0].toCharArray(), mnemonic);
            Assert.assertArrayEquals(example[1].toCharArray(), passphrase);
        }
    }

    @Test
    public void legacyAndStrictSpacingRemainDistinctAndDoNotRewriteSeedInput() {
        String spaced = "  " + VECTOR_MNEMONIC.replace("abandon about", "abandon  about") + " ";
        char[] characters = spaced.toCharArray();
        Assert.assertTrue(MnemonicUtils.validateMnemonicChars(characters));
        Assert.assertFalse(MnemonicUtils.validateMnemonicStrictChars(characters));
        Assert.assertArrayEquals(new byte[16], MnemonicUtils.generateEntropyFromChars(characters));
        Assert.assertArrayEquals(legacySeed(spaced, ""),
                MnemonicUtils.generateSeedFromChars(characters, null));
        Assert.assertFalse(Arrays.equals(MnemonicUtils.generateSeedFromChars(characters, null),
                MnemonicUtils.generateSeed(VECTOR_MNEMONIC, "")));
        for (String separator : new String[] {"\t", "\n", "\u00a0", "\u3000"}) {
            char[] invalid = VECTOR_MNEMONIC.replaceFirst(" ", separator).toCharArray();
            Assert.assertFalse(MnemonicUtils.validateMnemonicChars(invalid));
            Assert.assertFalse(MnemonicUtils.validateMnemonicStrictChars(invalid));
        }
        Assert.assertArrayEquals(spaced.toCharArray(), characters);
    }

    @Test
    public void failureLeavesBorrowedMnemonicUnchangedAndRejectsEmptySeedInput() {
        char[] invalidChecksum = VECTOR_MNEMONIC.replace("about", "abandon").toCharArray();
        char[] expected = invalidChecksum.clone();
        Assert.assertFalse(MnemonicUtils.validateMnemonicChars(invalidChecksum));
        try {
            MnemonicUtils.generateEntropyFromChars(invalidChecksum);
            Assert.fail("Expected checksum failure");
        } catch (IllegalArgumentException expectedFailure) {
            Assert.assertArrayEquals(expected, invalidChecksum);
        }
        for (char[] empty : new char[][] {null, {}, {' ', '\t', '\n', '\0'}}) {
            Assert.assertFalse(MnemonicUtils.validateMnemonicChars(empty));
            Assert.assertFalse(MnemonicUtils.validateMnemonicStrictChars(empty));
            try {
                MnemonicUtils.generateSeedFromChars(empty, null);
                Assert.fail("Expected empty mnemonic failure");
            } catch (IllegalArgumentException expectedFailure) {
                // Same String.trim()-based definition as the legacy entry point.
            }
        }
    }

    @Test
    public void resultOwnershipIsIndependentAcrossDerivationAndGenerationCalls() {
        char[] mnemonic = VECTOR_MNEMONIC.toCharArray();
        char[] passphrase = "TREZOR".toCharArray();
        byte[] firstSeed = MnemonicUtils.generateSeedFromChars(mnemonic, passphrase);
        byte[] secondSeed = MnemonicUtils.generateSeedFromChars(mnemonic, passphrase);
        SensitiveData.clear(firstSeed);
        Assert.assertEquals(VECTOR_SEED, Numeric.toHexStringNoPrefix(secondSeed));
        Assert.assertArrayEquals(VECTOR_MNEMONIC.toCharArray(), mnemonic);
        Assert.assertArrayEquals("TREZOR".toCharArray(), passphrase);
        char[] firstMnemonic = MnemonicUtils.generateMnemonicChars(new byte[16]);
        char[] secondMnemonic = MnemonicUtils.generateMnemonicChars(new byte[16]);
        SensitiveData.clear(firstMnemonic);
        Assert.assertArrayEquals(VECTOR_MNEMONIC.toCharArray(), secondMnemonic);
    }

    @Test
    public void nullPassphraseEqualsEmptyForBothEntrypoints() {
        Assert.assertArrayEquals(MnemonicUtils.generateSeed(VECTOR_MNEMONIC, null),
                MnemonicUtils.generateSeedFromChars(VECTOR_MNEMONIC.toCharArray(), new char[0]));
    }

    private static byte[] legacySeed(String mnemonic, String passphrase) {
        PKCS5S2ParametersGenerator generator =
                new PKCS5S2ParametersGenerator(new SHA512Digest());
        generator.init(Normalizer.normalize(mnemonic, Normalizer.Form.NFKD)
                        .getBytes(StandardCharsets.UTF_8),
                Normalizer.normalize("mnemonic" + passphrase, Normalizer.Form.NFKD)
                        .getBytes(StandardCharsets.UTF_8), 2048);
        return ((KeyParameter) generator.generateDerivedParameters(512)).getKey();
    }
}
