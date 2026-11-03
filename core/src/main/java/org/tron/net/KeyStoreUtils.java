package org.tron.net;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.RomUtils;
import org.tron.common.utils.SensitiveData;
import org.tron.walletserver.AddressUtil;
import org.tron.walletserver.Wallet;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String getKeyStoreWithPrivate(String password, Wallet wallet) throws CipherException {
        return getKeyStore(password, wallet.getECKey().getPrivKeyBytes(), wallet.getAddress());
    }

    public static String getKeyStoreWithMnemonic(String password, String mnemonic, String address) throws CipherException {
        char[] passwordChars = null;
        char[] mnemonicChars = null;
        try {
            passwordChars = password.toCharArray();
            mnemonicChars = mnemonic.toCharArray();
            return encryptMnemonicChars(passwordChars, mnemonicChars, address);
        } finally {
            SensitiveData.clear(passwordChars);
            SensitiveData.clear(mnemonicChars);
        }
    }

    // Compatibility API: consumes and zeroes the supplied plaintext on every exit.
    public static String getKeyStore(String password, byte[] bytes, String address) throws CipherException {
        char[] passwordChars = null;
        try {
            passwordChars = password.toCharArray();
            return encryptToKeyStore(passwordChars, bytes, address);
        } finally {
            SensitiveData.clear(passwordChars);
            SensitiveData.clear(bytes);
        }
    }

    /** Borrows both inputs without clearing them. The private key must be canonical 32-byte form. */
    public static String encryptPrivateKeyBytes(char[] password, byte[] privateKey, String address)
            throws CipherException {
        if (privateKey == null || privateKey.length != 32) {
            throw new CipherException("Private key must contain 32 bytes");
        }
        try {
            ECKey.fromPrivate(privateKey);
        } catch (IllegalArgumentException e) {
            throw new CipherException("Invalid private key", e);
        }
        return encryptToKeyStore(password, privateKey, address);
    }

    /** Borrows both inputs. Only this method's UTF-8 plaintext copy is cleared. */
    public static String encryptMnemonicChars(char[] password, char[] mnemonic, String address)
            throws CipherException {
        byte[] mnemonicBytes = null;
        try {
            mnemonicBytes = SensitiveData.toUtf8Bytes(mnemonic);
            return encryptToKeyStore(password, mnemonicBytes, address);
        } finally {
            SensitiveData.clear(mnemonicBytes);
        }
    }

    private static String encryptToKeyStore(char[] password, byte[] bytes, String address)
            throws CipherException {
        byte[] passwordBytes = null;
        byte[] derivedKey = null;
        byte[] encryptKey = null;
        try {
            final int n = RomUtils.getTotalMemory() > 2 ? 1 << 16 : 1 << 14;
            final int p = 1;
            final int r = 8;
            // Preserve the Web3 v3 format and the fixed 32-byte derived key and salt.
            byte[] salt = generateRandomBytes(32);
            // Keystore passwords use raw UTF-8, without BIP39/NFKD normalization.
            passwordBytes = SensitiveData.toUtf8Bytes(password);
            derivedKey = generateDerivedScryptKey(passwordBytes, salt, n, r, p, 32);
            encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
            byte[] iv = generateRandomBytes(16);
            byte[] cipherText = performCipherOperation(Cipher.ENCRYPT_MODE, iv, encryptKey, bytes);
            byte[] mac = generateMac(derivedKey, cipherText);
            if (AddressUtil.isEmpty(address)) {
                return "";
            }
            String hexAddress = address;
            if (AddressUtil.isAddressValid(address)) {
                hexAddress = Hex.toHexString(AddressUtil.decodeFromBase58Check(address));
            }
            return WalletFile.createGson().toJson(
                    createWalletFile(hexAddress, cipherText, iv, salt, mac, n, p));
        } finally {
            // Includes encoding, KDF and cipher failure paths. The plaintext is borrowed.
            SensitiveData.clear(passwordBytes);
            SensitiveData.clear(derivedKey);
            SensitiveData.clear(encryptKey);
        }
    }

    // Malformed JSON/hex may retain the legacy unchecked parsing exceptions.
    public static String getPrivateWithKeyStore(String keyStore, String password) throws CipherException, IOException {
        char[] passwordChars = null;
        byte[] privateKey = null;
        try {
            passwordChars = password.toCharArray();
            privateKey = decryptPrivateKeyBytes(keyStore, passwordChars);
            return ByteArray.toHexString(privateKey);
        } finally {
            SensitiveData.clear(passwordChars);
            SensitiveData.clear(privateKey);
        }
    }

    /** Borrows password; returns a validated 32-byte key owned and cleared by the caller. */
    public static byte[] decryptPrivateKeyBytes(String keyStore, char[] password)
            throws CipherException, IOException {
        WalletFile walletFile = WalletFile.createGson().fromJson(keyStore, WalletFile.class);
        byte[] plaintext = null;
        try {
            plaintext = decryptToByte(password, walletFile);
            ECKey ecKey = ECKey.fromPrivate(plaintext);
            validateAddressMatches(walletFile.getAddress(), ecKey);
            // Keep importing historical non-canonical encodings as the legacy API did.
            if (plaintext.length != 32) {
                return ecKey.getPrivKeyBytes();
            }
            byte[] result = plaintext;
            plaintext = null;
            return result;
        } finally {
            SensitiveData.clear(plaintext);
        }
    }

    static void validateAddressMatches(String address, ECKey decryptedKey)
            throws AddressMismatchException {
        // accepted (S-04): Some third-party wallet keystores omit the optional address field.
        // Keep those files importable for compatibility; password, MAC and private-key checks
        // still apply, while address binding is enforced whenever a non-empty address is present.
        if (address == null || address.trim().isEmpty()) {
            return;
        }

        byte[] declaredAddress = AddressUtil.decodeUnknownAddress(address);
        if (declaredAddress == null
                || decryptedKey == null
                || !MessageDigest.isEqual(declaredAddress, decryptedKey.getAddress())) {
            throw new AddressMismatchException();
        }
    }

    public static String getMnemonicWithKeyStore(String keyStore, String password) throws CipherException, IOException {
        char[] passwordChars = null;
        char[] mnemonic = null;
        try {
            passwordChars = password.toCharArray();
            mnemonic = decryptMnemonicChars(keyStore, passwordChars);
            return new String(mnemonic);
        } finally {
            SensitiveData.clear(passwordChars);
            SensitiveData.clear(mnemonic);
        }
    }

    /** Borrows password; the returned mnemonic belongs to the caller and must be cleared. */
    public static char[] decryptMnemonicChars(String keyStore, char[] password)
            throws CipherException, IOException {
        byte[] mnemonicBytes = null;
        try {
            mnemonicBytes = decryptToByte(password,
                    WalletFile.createGson().fromJson(keyStore, WalletFile.class));
            return SensitiveData.fromUtf8Bytes(mnemonicBytes);
        } finally {
            SensitiveData.clear(mnemonicBytes);
        }
    }

    private static byte[] decryptToByte(char[] password, WalletFile walletFile)
            throws CipherException {
        byte[] passwordBytes = null;
        byte[] derivedKey = null;
        byte[] encryptKey = null;
        byte[] derivedMac = null;
        try {
            validate(walletFile);
            WalletFile.Crypto crypto = walletFile.getCrypto();
            byte[] mac = ByteArray.fromHexString(crypto.getMac());
            byte[] iv = ByteArray.fromHexString(crypto.getCipherparams().getIv());
            byte[] cipherText = ByteArray.fromHexString(crypto.getCiphertext());
            // Preserve the exact password bytes used by existing keystores.
            passwordBytes = SensitiveData.toUtf8Bytes(password);
            WalletFile.KdfParams kdfParams = crypto.getKdfparams();
            if (kdfParams instanceof WalletFile.ScryptKdfParams) {
                WalletFile.ScryptKdfParams scryptKdfParams =
                        (WalletFile.ScryptKdfParams) crypto.getKdfparams();
                int dklen = scryptKdfParams.getDklen();
                int n = scryptKdfParams.getN();
                int p = scryptKdfParams.getP();
                int r = scryptKdfParams.getR();
                // KDF params come from untrusted keystore JSON: a huge N allocates
                // 128*N*R bytes (OOM), and a non-power-of-two N makes SCrypt throw an
                // undeclared IllegalArgumentException bypassing the CipherException contract.
                if (n <= 1 || n > (1 << 20) || Integer.bitCount(n) != 1) {
                    throw new CipherException("Invalid scrypt n parameter");
                }
                if (r < 1 || r > 64) {
                    throw new CipherException("Invalid scrypt r parameter");
                }
                if (p < 1 || p > 16) {
                    throw new CipherException("Invalid scrypt p parameter");
                }
                // accepted: [S-04 2026-07-14, reopened as S-07 2026-08-11, re-accepted 2026-08-12]
                // Combined KDF resource budget (128*N*r scrypt memory, PBKDF2 iteration CPU) is
                // not enforced beyond the per-parameter caps above, so user-pasted keystore JSON
                // can request ~8 GiB / tens of seconds of KDF work before the MAC check. Worst
                // case is a local availability hit (OOM/ANR) on the importing user's own device —
                // no key material, signing or asset path is exposed — and tighter combined caps
                // risk rejecting odd-but-legitimate third-party keystores.
                // generateMac reads derivedKey[16..32), so anything below 32 is unusable.
                // Upper bound stays generous: legacy keystores were created with
                // DKLEN = plaintext length, so a mnemonic keystore stores dklen equal to
                // the mnemonic byte length (a 21/24-word mnemonic exceeds 128 bytes).
                // dklen is only the final PBKDF2 output length and does not drive scrypt's
                // 128*N*R memory cost, so a large value is cheap; 1024 keeps old wallets
                // decryptable while still rejecting absurd values.
                if (dklen < 32 || dklen > 1024) {
                    throw new CipherException("Invalid scrypt dklen parameter");
                }
                if (scryptKdfParams.getSalt() == null) {
                    throw new CipherException("Malformed keystore: missing scrypt salt");
                }
                byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
                derivedKey = generateDerivedScryptKey(passwordBytes, salt, n, r, p, dklen);
            } else if (kdfParams instanceof WalletFile.Aes128CtrKdfParams) {
                WalletFile.Aes128CtrKdfParams aes128CtrKdfParams =
                        (WalletFile.Aes128CtrKdfParams) crypto.getKdfparams();
                int c = aes128CtrKdfParams.getC();
                String prf = aes128CtrKdfParams.getPrf();
                // PBKDF2 iteration count comes from untrusted keystore JSON. A tiny c (e.g. 0/1)
                // makes password derivation nearly free, weakening offline brute-force resistance;
                // an excessive c causes a local DoS. Mirror the scrypt branch's parameter bounds.
                if (c < 10000 || c > (1 << 24)) {
                    throw new CipherException("Invalid pbkdf2 c parameter");
                }
                if (aes128CtrKdfParams.getSalt() == null) {
                    throw new CipherException("Malformed keystore: missing pbkdf2 salt");
                }
                byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

                derivedKey = generateAes128CtrDerivedKey(passwordBytes, salt, c, prf);
            } else {
                throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
            }

            derivedMac = generateMac(derivedKey, cipherText);
            if (!MessageDigest.isEqual(derivedMac, mac)) {
                throw new CipherException("Invalid password provided");
            }
            encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
            // The plaintext is transferred to the caller only after MAC verification.
            return performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);
        } finally {
            SensitiveData.clear(passwordBytes);
            SensitiveData.clear(derivedKey);
            SensitiveData.clear(encryptKey);
            SensitiveData.clear(derivedMac);
        }
    }

    private static byte[] generateAes128CtrDerivedKey(
            byte[] password, byte[] salt, int c, String prf) throws CipherException {

        if (!"hmac-sha256".equals(prf)) {
            throw new CipherException("Unsupported prf:" + prf);
        }

        // Java 8 supports this, but you have to convert the password to a character array, see
        // http://stackoverflow.com/a/27928435/3211687

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password, salt, c);
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }


    private static void validate(WalletFile walletFile) throws CipherException {
        final int CURRENT_VERSION = 3;
        final String CIPHER = "aes-128-ctr";

        final String AES_128_CTR = "pbkdf2";
        final String SCRYPT = "scrypt";

        // Keystore JSON is user-pasted input: Gson may return null or leave any
        // field null, which must surface as the declared CipherException, not NPE.
        if (walletFile == null) {
            throw new CipherException("Malformed keystore: empty content");
        }
        WalletFile.Crypto crypto = walletFile.getCrypto();
        if (crypto == null
                || crypto.getCipher() == null
                || crypto.getKdf() == null
                || crypto.getKdfparams() == null
                || crypto.getCiphertext() == null
                || crypto.getMac() == null
                || crypto.getCipherparams() == null
                || crypto.getCipherparams().getIv() == null) {
            throw new CipherException("Malformed keystore: missing crypto fields");
        }

        if (walletFile.getVersion() != CURRENT_VERSION) {
            throw new CipherException("Wallet version is not supported");
        }

        if (!crypto.getCipher().equals(CIPHER)) {
            throw new CipherException("Wallet cipher is not supported");
        }

        if (!crypto.getKdf().equals(AES_128_CTR) && !crypto.getKdf().equals(SCRYPT)) {
            throw new CipherException("KDF type is not supported");
        }
    }


    private static WalletFile createWalletFile(
            String hexAddress, byte[] cipherText, byte[] iv, byte[] salt, byte[] mac,
            int n, int p) {
        final String CIPHER = "aes-128-ctr";
        final String SCRYPT = "scrypt";
        final int DKLEN = 32;
        final int CURRENT_VERSION = 3;
        final int R = 8;
        WalletFile walletFile = new WalletFile();
        // walletFile.setAddress(StringTronUtil.encode58Check(ecKeyPair.getAddress()));
//        walletFile.setAddress(Hex.toHexString(ecKeyPair.getAddress()));
        walletFile.setAddress(hexAddress);

        WalletFile.Crypto crypto = new WalletFile.Crypto();
        crypto.setCipher(CIPHER);
        crypto.setCiphertext(ByteArray.toHexString(cipherText));
        walletFile.setCrypto(crypto);

        WalletFile.CipherParams cipherParams = new WalletFile.CipherParams();
        cipherParams.setIv(ByteArray.toHexString(iv));
        crypto.setCipherparams(cipherParams);

        crypto.setKdf(SCRYPT);
        WalletFile.ScryptKdfParams kdfParams = new WalletFile.ScryptKdfParams();
        kdfParams.setDklen(DKLEN);
        kdfParams.setN(n);
        kdfParams.setP(p);
        kdfParams.setR(R);
        kdfParams.setSalt(ByteArray.toHexString(salt));
        crypto.setKdfparams(kdfParams);

        crypto.setMac(ByteArray.toHexString(mac));
        walletFile.setCrypto(crypto);
        walletFile.setId(UUID.randomUUID().toString());
        walletFile.setVersion(CURRENT_VERSION);

        return walletFile;
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt, int n, int r, int p, int dkLen) throws CipherException {
        return SCrypt.generate(password, salt, n, r, p, dkLen);
    }

    private static byte[] performCipherOperation(
            int mode, byte[] iv, byte[] encryptKey, byte[] text) throws CipherException {

        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(mode, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(text);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new CipherException("Error performing cipher operation", e);
        }
    }

    private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
        byte[] result = new byte[16 + cipherText.length];
        try {
            System.arraycopy(derivedKey, 16, result, 0, 16);
            System.arraycopy(cipherText, 0, result, 16, cipherText.length);
            return Hash.sha3(result);
        } finally {
            SensitiveData.clear(result);
        }
    }
}
