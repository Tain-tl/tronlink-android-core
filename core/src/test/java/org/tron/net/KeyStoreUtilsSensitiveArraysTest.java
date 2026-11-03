package org.tron.net;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.walletserver.AddressUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreUtilsSensitiveArraysTest {

    private static final String PASSWORD = "p\u00e4ss\u00e9 \uD83D\uDD10";
    private static final String ADDRESS = AddressUtil.encode58Check(
            ECKey.fromPrivate(BigInteger.ONE).getAddress());

    @Test
    public void privateKeyArrayRoundTrip_borrowsInputsAndKeepsLegacyReaders() throws Exception {
        char[] password = PASSWORD.toCharArray();
        byte[] privateKey = privateKeyOne();
        String keyStore = KeyStoreUtils.encryptPrivateKeyBytes(password, privateKey, ADDRESS);

        Assert.assertArrayEquals(PASSWORD.toCharArray(), password);
        Assert.assertArrayEquals(privateKeyOne(), privateKey);
        WalletFile file = parse(keyStore);
        Assert.assertEquals(3, file.getVersion());
        Assert.assertEquals("aes-128-ctr", file.getCrypto().getCipher());
        Assert.assertEquals("scrypt", file.getCrypto().getKdf());
        Assert.assertEquals(32, file.getCrypto().getKdfparams().getDklen());
        Assert.assertEquals(32, Hex.decode(file.getCrypto().getKdfparams().getSalt()).length);
        Assert.assertArrayEquals(privateKey, KeyStoreUtils.decryptPrivateKeyBytes(keyStore, password));
        Assert.assertEquals(Hex.toHexString(privateKey),
                KeyStoreUtils.getPrivateWithKeyStore(keyStore, PASSWORD));
        byte[] first = KeyStoreUtils.decryptPrivateKeyBytes(keyStore, password);
        Arrays.fill(first, (byte) 0);
        Assert.assertArrayEquals(privateKey,
                KeyStoreUtils.decryptPrivateKeyBytes(keyStore, password));
        Assert.assertArrayEquals(PASSWORD.toCharArray(), password);
    }

    @Test
    public void mnemonicArrayRoundTrip_preservesUnicodeWhitespaceAndRawPassword() throws Exception {
        String text = "  \u00e9 日本 \uD83D\uDD10\t alpha\n";
        char[] mnemonic = text.toCharArray();
        char[] password = "\u00e9".toCharArray();
        String keyStore = KeyStoreUtils.encryptMnemonicChars(password, mnemonic, ADDRESS);

        Assert.assertArrayEquals(text.toCharArray(), mnemonic);
        Assert.assertArrayEquals("\u00e9".toCharArray(), password);
        Assert.assertArrayEquals(mnemonic, KeyStoreUtils.decryptMnemonicChars(keyStore, password));
        Assert.assertEquals(text, KeyStoreUtils.getMnemonicWithKeyStore(keyStore, "\u00e9"));
        assertWrongPassword(keyStore, "e\u0301".toCharArray());
        char[] first = KeyStoreUtils.decryptMnemonicChars(keyStore, password);
        Arrays.fill(first, '\0');
        Assert.assertArrayEquals(mnemonic, KeyStoreUtils.decryptMnemonicChars(keyStore, password));
    }

    @Test
    public void legacyEncryption_consumesPlaintextOnSuccessAndEarlyFailure() throws Exception {
        byte[] plaintext = privateKeyOne();
        String keyStore = KeyStoreUtils.getKeyStore(PASSWORD, plaintext, ADDRESS);
        Assert.assertArrayEquals(new byte[32], plaintext);
        Assert.assertArrayEquals(privateKeyOne(),
                KeyStoreUtils.decryptPrivateKeyBytes(keyStore, PASSWORD.toCharArray()));

        byte[] failedPlaintext = privateKeyOne();
        try {
            KeyStoreUtils.getKeyStore(null, failedPlaintext, ADDRESS);
            Assert.fail("null password must fail");
        } catch (NullPointerException expected) {
            Assert.assertArrayEquals(new byte[32], failedPlaintext);
        }
    }

    @Test
    public void legacyMnemonicWriter_isReadableByArrayApi() throws Exception {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String keyStore = KeyStoreUtils.getKeyStoreWithMnemonic(PASSWORD, mnemonic, ADDRESS);
        Assert.assertArrayEquals(mnemonic.toCharArray(),
                KeyStoreUtils.decryptMnemonicChars(keyStore, PASSWORD.toCharArray()));
    }

    @Test
    public void historicalScryptMnemonicWithVariableDklen_remainsReadable() throws Exception {
        String text = "abandon ".repeat(23) + "art";
        WalletFile file = fixture(text.getBytes(StandardCharsets.UTF_8), true, 256);
        String json = json(file);
        Assert.assertArrayEquals(text.toCharArray(),
                KeyStoreUtils.decryptMnemonicChars(json, PASSWORD.toCharArray()));
        Assert.assertEquals(text, KeyStoreUtils.getMnemonicWithKeyStore(json, PASSWORD));
    }

    @Test
    public void pbkdf2PrivateKey_readersValidateAddressAndKeepHistoricalCanonicalization()
            throws Exception {
        for (byte[] encoded : new byte[][]{privateKeyOne(), new byte[]{1}, leadingZeroKey()}) {
            WalletFile file = fixture(encoded, false, 32);
            Assert.assertArrayEquals(privateKeyOne(),
                    KeyStoreUtils.decryptPrivateKeyBytes(json(file), PASSWORD.toCharArray()));
            Assert.assertEquals(Hex.toHexString(privateKeyOne()),
                    KeyStoreUtils.getPrivateWithKeyStore(json(file), PASSWORD));
        }
        WalletFile optionalAddress = fixture(privateKeyOne(), false, 32);
        optionalAddress.setAddress(null);
        Assert.assertArrayEquals(privateKeyOne(), KeyStoreUtils.decryptPrivateKeyBytes(
                json(optionalAddress), PASSWORD.toCharArray()));

        WalletFile mismatch = fixture(privateKeyOne(), false, 32);
        mismatch.setAddress(Hex.toHexString(ECKey.fromPrivate(BigInteger.TWO).getAddress()));
        char[] password = PASSWORD.toCharArray();
        try {
            KeyStoreUtils.decryptPrivateKeyBytes(json(mismatch), password);
            Assert.fail("address mismatch must fail");
        } catch (AddressMismatchException expected) {
            Assert.assertArrayEquals(PASSWORD.toCharArray(), password);
        }
        try {
            KeyStoreUtils.getPrivateWithKeyStore(json(mismatch), PASSWORD);
            Assert.fail("legacy reader must keep address validation");
        } catch (AddressMismatchException expected) {
            Assert.assertTrue(expected.getMessage().contains("address"));
        }
    }

    @Test
    public void invalidPrivateKeys_areRejectedWithoutClearingBorrowedInputs() throws Exception {
        for (byte[] privateKey : new byte[][]{new byte[32], Hex.decode(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
                new byte[]{1}}) {
            byte[] original = privateKey.clone();
            char[] password = PASSWORD.toCharArray();
            try {
                KeyStoreUtils.encryptPrivateKeyBytes(password, privateKey, ADDRESS);
                Assert.fail("invalid private key must fail");
            } catch (CipherException expected) {
                Assert.assertArrayEquals(original, privateKey);
                Assert.assertArrayEquals(PASSWORD.toCharArray(), password);
            }
        }
        WalletFile zeroKey = fixture(new byte[32], false, 32);
        try {
            KeyStoreUtils.decryptPrivateKeyBytes(json(zeroKey), PASSWORD.toCharArray());
            Assert.fail("zero private key in encrypted plaintext must fail");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("secp256k1"));
        }
    }

    @Test
    public void decryptFailures_leavePasswordBorrowedAndKeepMacAndCipherChecks() throws Exception {
        WalletFile file = fixture(privateKeyOne(), false, 32);
        String goodJson = json(file);
        assertWrongPassword(goodJson, "incorrect".toCharArray());
        file.getCrypto().setMac("00".repeat(32));
        assertCipherFailure(json(file), "Invalid password");
        file = parse(goodJson);
        file.getCrypto().getCipherparams().setIv("00");
        assertCipherFailure(json(file), "cipher operation");
        file = parse(goodJson);
        ((WalletFile.Aes128CtrKdfParams) file.getCrypto().getKdfparams()).setC(1);
        assertCipherFailure(json(file), "pbkdf2 c");
        file = parse(goodJson);
        ((WalletFile.Aes128CtrKdfParams) file.getCrypto().getKdfparams()).setPrf("unsupported");
        assertCipherFailure(json(file), "Unsupported prf");
        Assert.assertArrayEquals(privateKeyOne(),
                KeyStoreUtils.decryptPrivateKeyBytes(goodJson, PASSWORD.toCharArray()));
    }

    private static void assertWrongPassword(String keyStore, char[] password) throws Exception {
        char[] original = password.clone();
        try {
            KeyStoreUtils.decryptMnemonicChars(keyStore, password);
            Assert.fail("wrong password must fail");
        } catch (CipherException expected) {
            Assert.assertTrue(expected.getMessage().contains("Invalid password"));
            Assert.assertArrayEquals(original, password);
        }
    }

    private static void assertCipherFailure(String keyStore, String message) throws Exception {
        char[] password = PASSWORD.toCharArray();
        try {
            KeyStoreUtils.decryptPrivateKeyBytes(keyStore, password);
            Assert.fail("malformed keystore must fail");
        } catch (CipherException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains(message));
            Assert.assertArrayEquals(PASSWORD.toCharArray(), password);
        }
    }

    // Build an independent v3 keystore with the legacy raw UTF-8 password and cipher recipe.
    private static WalletFile fixture(byte[] plaintext, boolean scrypt, int dklen) throws Exception {
        byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] iv = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);
        byte[] derived = null;
        byte[] encryptionKey = null;
        byte[] macInput = null;
        try {
            WalletFile.Crypto crypto = new WalletFile.Crypto();
            if (scrypt) {
                WalletFile.ScryptKdfParams params = new WalletFile.ScryptKdfParams();
                params.setN(16);
                params.setR(1);
                params.setP(1);
                params.setDklen(dklen);
                params.setSalt(Hex.toHexString(salt));
                crypto.setKdf("scrypt");
                crypto.setKdfparams(params);
                derived = SCrypt.generate(passwordBytes, salt, 16, 1, 1, dklen);
            } else {
                WalletFile.Aes128CtrKdfParams params = new WalletFile.Aes128CtrKdfParams();
                params.setC(10000);
                params.setDklen(32);
                params.setPrf("hmac-sha256");
                params.setSalt(Hex.toHexString(salt));
                crypto.setKdf("pbkdf2");
                crypto.setKdfparams(params);
                PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
                generator.init(passwordBytes, salt, 10000);
                derived = ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
            }
            encryptionKey = Arrays.copyOfRange(derived, 0, 16);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                    new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(plaintext);
            macInput = new byte[16 + encrypted.length];
            System.arraycopy(derived, 16, macInput, 0, 16);
            System.arraycopy(encrypted, 0, macInput, 16, encrypted.length);
            WalletFile.CipherParams cipherParams = new WalletFile.CipherParams();
            cipherParams.setIv(Hex.toHexString(iv));
            crypto.setCipher("aes-128-ctr");
            crypto.setCipherparams(cipherParams);
            crypto.setCiphertext(Hex.toHexString(encrypted));
            crypto.setMac(Hex.toHexString(Hash.sha3(macInput)));
            WalletFile file = new WalletFile();
            file.setAddress(ADDRESS);
            file.setVersion(3);
            file.setCrypto(crypto);
            return file;
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            if (derived != null) Arrays.fill(derived, (byte) 0);
            if (encryptionKey != null) Arrays.fill(encryptionKey, (byte) 0);
            if (macInput != null) Arrays.fill(macInput, (byte) 0);
        }
    }

    private static byte[] privateKeyOne() {
        byte[] key = new byte[32];
        key[31] = 1;
        return key;
    }

    private static byte[] leadingZeroKey() {
        byte[] key = new byte[33];
        key[32] = 1;
        return key;
    }

    private static WalletFile parse(String json) {
        return WalletFile.createGson().fromJson(json, WalletFile.class);
    }

    private static String json(WalletFile file) {
        return WalletFile.createGson().toJson(file);
    }
}
