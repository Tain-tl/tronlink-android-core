package org.tron.walletserver;

import static org.tron.common.bip32.Bip32ECKeyPair.HARDENED_BIT;

import androidx.annotation.NonNull;


import org.tron.common.bip32.Bip32ECKeyPair;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.MnemonicUtils;
import org.tron.common.utils.SensitiveData;
import org.tron.common.utils.GsonFormatUtils;
import org.tron.common.utils.LogUtils;
import org.tron.common.utils.Utils;
import org.tron.config.Parameter;

import java.security.SecureRandom;
import java.util.Arrays;

public class Wallet implements Comparable<Wallet> {

    private volatile ECKey mECKey = null;

    private boolean isWatchOnly = false;
    private boolean isShieldedWallet = false;
    private String walletName = "";
    private String encPassword = "";
    public String address = "";
    private transient byte[] encPrivateKey;
    private transient byte[] privateKeyBytes33;


    private byte[] publicKey;
    private String iconRes;//Avatar
    private boolean isBackUp;//whether  backed up
    private transient char[] mnemonicChars;
    private String keyStore;
    private int createType = -1;// tronconfig type
    private long createTime;
    private int color = -1;
    private static final String TAG = "Wallet";
    private String mnemonicPath;


    public String getMnemonicPathString() {
        return mnemonicPath;
    }

    /**
     * @param mnemonicPath WalletPath.class json
     */
    public void setMnemonicPath(String mnemonicPath) {
        this.mnemonicPath = mnemonicPath;
    }

    public int getMnemonicLength() {
        return mnemonicLength;
    }

    public void setMnemonicLength(int mnemonicLength) {
        this.mnemonicLength = mnemonicLength;
    }

    private int mnemonicLength;

    public int getColor() {
        return color;
    }

    public void setColor(int color) {
        this.color = color;
    }

    /** Legacy text export. Prefer {@link #copyMnemonicChars()} and clear the owned result. */
    public String getMnemonic() {
        char[] copy = copyMnemonicChars();
        try {
            return copy == null ? null : new String(copy);
        } finally {
            SensitiveData.clear(copy);
        }
    }

    /** Legacy adapter. The caller's immutable String cannot be cleared by this wallet. */
    public void setMnemonic(String mnemonic) {
        char[] copy = mnemonic == null ? null : mnemonic.toCharArray();
        try {
            setMnemonicChars(copy);
        } finally {
            SensitiveData.clear(copy);
        }
    }

    /** Borrows the input and stores an independent copy, clearing any previous owned phrase. */
    public synchronized void setMnemonicChars(char[] mnemonic) {
        char[] replacement = mnemonic == null ? null : mnemonic.clone();
        SensitiveData.clear(mnemonicChars);
        mnemonicChars = replacement;
    }

    /** Returns an owned copy. The caller must clear it after use. */
    public synchronized char[] copyMnemonicChars() {
        return mnemonicChars == null ? null : mnemonicChars.clone();
    }

    public boolean isBackUp() {
        return isBackUp;
    }

    public void setBackUp(boolean backUp) {
        isBackUp = backUp;
    }

    public String getIconRes() {
        return iconRes;
    }

    public void setIconRes(String iconRes) {
        this.iconRes = iconRes;
    }

    public boolean isShieldedWallet() {
        return isShieldedWallet;
    }

    public void setShieldedWallet(boolean shieldedWallet) {
        isShieldedWallet = shieldedWallet;
    }


    public Wallet() {
    }

    public Wallet(boolean generateECKey) {
        if (generateECKey) {
            generateWallet(Utils.getRandom());
        }
    }

    // Package-private to allow deterministic verification of entropy-source failure handling.
    Wallet(boolean generateECKey, SecureRandom secureRandom) {
        if (generateECKey) {
            generateWallet(secureRandom);
        }
    }

    private void generateWallet(SecureRandom secureRandom) {
        byte[] initialEntropy = new byte[16];
        byte[] seed = null;
        try {
            secureRandom.nextBytes(initialEntropy);
            MnemonicUtils.validateGeneratedEntropyQuality(initialEntropy);
            mnemonicChars = MnemonicUtils.generateMnemonicChars(initialEntropy);
            seed = MnemonicUtils.generateSeedFromChars(mnemonicChars, null);

            Bip32ECKeyPair masterKeypair = Bip32ECKeyPair.generateKeyPair(seed);
            Bip32ECKeyPair bip44Keypair = generateBip44KeyPair(masterKeypair);
            privateKeyBytes33 = bip44Keypair.getPrivateKeyBytes33();
            mECKey = ECKey.fromPrivate(privateKeyBytes33);
        } catch (RuntimeException ex) {
            clearSensitiveData();
            // Do not log entropy, mnemonic, seed, or private-key material.
            LogUtils.e(TAG, "Wallet generation aborted: " + ex.getClass().getSimpleName());
            throw new IllegalStateException("Failed to generate wallet securely", ex);
        } finally {
            Arrays.fill(initialEntropy, (byte) 0);
            if (seed != null) {
                Arrays.fill(seed, (byte) 0);
            }
        }
    }


    public Wallet(I_TYPE I_Type, String key) {
        char[] chars = key == null ? null : key.toCharArray();
        try {
            initializeFromChars(I_Type, chars);
        } finally {
            SensitiveData.clear(chars);
        }
    }


    public Wallet(String mnemonic, WalletPath walletPath) {
        char[] chars = mnemonic == null ? null : mnemonic.toCharArray();
        try {
            initializeMnemonicPath(chars, walletPath);
        } finally {
            SensitiveData.clear(chars);
        }
    }

    /** Borrows the input; invalid keys return a closed wallet, matching the legacy constructor. */
    public static Wallet fromPrivateKeyChars(char[] privateKey) {
        Wallet wallet = new Wallet();
        wallet.initializeFromChars(I_TYPE.PRIVATE, privateKey);
        return wallet;
    }

    /** Borrows a canonical 32-byte key and stores only independent key material. */
    public static Wallet fromPrivateKeyBytes(byte[] privateKey) {
        Wallet wallet = new Wallet();
        if (privateKey != null && privateKey.length == 32) {
            try {
                ECKey key = ECKey.fromPrivate(privateKey);
                byte[] exported = key.getPrivKeyBytes();
                wallet.mECKey = key;
                wallet.privateKeyBytes33 = exported;
            } catch (RuntimeException ex) {
                wallet.clearSensitiveData();
            }
        }
        return wallet;
    }

    /** Legacy-compatible derivation; the phrase is borrowed and is not retained. */
    public static Wallet fromMnemonicChars(char[] mnemonic) {
        Wallet wallet = new Wallet();
        wallet.initializeFromChars(I_TYPE.MNEMONIC, mnemonic);
        return wallet;
    }

    /** Strict BIP39 import; the phrase is borrowed and is not retained. */
    public static Wallet fromMnemonicStrictChars(char[] mnemonic) {
        Wallet wallet = new Wallet();
        wallet.initializeFromChars(I_TYPE.MNEMONIC_STRICT_VERIFICATION, mnemonic);
        return wallet;
    }

    /** Custom-path derivation, retaining an independent phrase copy like the legacy constructor. */
    public static Wallet fromMnemonicChars(char[] mnemonic, WalletPath walletPath) {
        Wallet wallet = new Wallet();
        wallet.initializeMnemonicPath(mnemonic, walletPath);
        return wallet;
    }

    private void initializeFromChars(I_TYPE type, char[] key) {
        if (type == I_TYPE.PRIVATE) {
            generateKeyForPrivateKey(key);
        } else if (type == I_TYPE.MNEMONIC || type == I_TYPE.MNEMONIC_STRICT_VERIFICATION) {
            generateKeyForMnemonic(key, 44, 195, 0, 0, 0,
                    type == I_TYPE.MNEMONIC_STRICT_VERIFICATION);
        }
    }

    private void initializeMnemonicPath(char[] mnemonic, WalletPath walletPath) {
        if (legacyEmpty(mnemonic) || walletPath == null) return;
        if (generateKeyForMnemonic(mnemonic, walletPath.purpose, walletPath.coinType,
                walletPath.account, walletPath.change, walletPath.accountIndex, false)) {
            setMnemonicPath(GsonFormatUtils.toGsonString(walletPath));
            setMnemonicChars(mnemonic);
        }
    }

    private static boolean legacyEmpty(char[] value) {
        if (value == null) return true;
        int start = 0;
        int end = value.length;
        while (start < end && value[start] <= ' ') start++;
        while (end > start && value[end - 1] <= ' ') end--;
        return start == end || (end - start == 4 && value[start] == 'n'
                && value[start + 1] == 'u' && value[start + 2] == 'l' && value[start + 3] == 'l');
    }

    public boolean isOpen() {
        ECKey key = mECKey;
        return key != null && key.hasPrivKey();
    }


    public byte[] getPublicKey() {
        ECKey key = mECKey;
        return key != null ? key.getPubKey() : publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPrivateKey() {
        ECKey key = mECKey;
        return key != null ? key.getPrivKeyBytes() : null;
    }

    /**
     * Derives the EC key from a hex-encoded private key.
     *
     * @return {@code true} if a key was successfully derived; {@code false} when the
     * input is empty/null or derivation fails. On failure {@code mECKey} is left null,
     * so callers must check this result (or {@link #isOpen()}) before continuing a
     * sensitive flow rather than assuming a key is present.
     */
    private boolean generateKeyForPrivateKey(char[] privateKey) {
        if (privateKey == null) return false;
        int offset = privateKey.length >= 2 && privateKey[0] == '0'
                && (privateKey[1] == 'x' || privateKey[1] == 'X') ? 2 : 0;
        if (privateKey.length - offset != 64) return false;
        byte[] decoded = new byte[32];
        try {
            for (int i = 0; i < decoded.length; i++) {
                int high = hexDigit(privateKey[offset + i * 2]);
                int low = hexDigit(privateKey[offset + i * 2 + 1]);
                if (high < 0 || low < 0) return false;
                decoded[i] = (byte) ((high << 4) | low);
            }
            ECKey key = ECKey.fromPrivate(decoded);
            byte[] exported = key.getPrivKeyBytes();
            mECKey = key;
            privateKeyBytes33 = exported;
            return true;
        } catch (RuntimeException ex) {
            return false;
        } finally {
            SensitiveData.clear(decoded);
        }
    }

    private static int hexDigit(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }

    /**
     * @param mnemonic
     * @param purpose      default 44 (Documentation source from  BIP43)
     * @param coinType     TRON default 195
     * @param account      default 0
     * @param change       default 0
     * @param accountIndex default 0
     * @return {@code true} if a key was successfully derived; {@code false} when the
     * mnemonic is empty/null or derivation fails. This legacy entry point intentionally
     * accepts non-BIP-39 phrases for backward compatibility. Use
     * {@link I_TYPE#MNEMONIC_STRICT_VERIFICATION} when importing a mnemonic that must pass
     * complete BIP-39 word-list and checksum validation. On failure {@code mECKey} is left
     * null, so callers must check this result (or {@link #isOpen()}) before continuing a
     * sensitive flow rather than assuming a key is present.
     */
    private boolean generateKeyForMnemonic(char[] mnemonic, int purpose, int coinType,
            int account, int change, int accountIndex, boolean strictVerification) {
        boolean isAccepted = mnemonic != null
                && mnemonic.length != 0
                && (!strictVerification || MnemonicUtils.validateMnemonicStrictChars(mnemonic));
        if (isAccepted) {
            byte[] seed = null;
            byte[] derivedPrivate = null;
            try {
                WalletPath.validate(purpose, coinType, account, change, accountIndex);
                seed = MnemonicUtils.generateSeedFromChars(mnemonic, null);
                Bip32ECKeyPair masterKeypair = Bip32ECKeyPair.generateKeyPair(seed);
                Bip32ECKeyPair bip44Keypair = generateBip44KeyPair(masterKeypair, purpose, coinType, account, change, accountIndex);
                derivedPrivate = bip44Keypair.getPrivateKeyBytes33();
                ECKey key = ECKey.fromPrivate(derivedPrivate);
                mECKey = key;
                privateKeyBytes33 = derivedPrivate;
                derivedPrivate = null;
                return true;
            } catch (Exception ex) {
                // Keep failure logging minimal: record the exception type only.
                LogUtils.e(TAG, "generateKeyForMnemonic failed: " + ex.getClass().getSimpleName());
                return false;
            } finally {
                SensitiveData.clear(seed);
                SensitiveData.clear(derivedPrivate);
            }
        } else {
            mECKey = null;
            privateKeyBytes33 = null;
            return false;
        }
    }

    public int getCreateType() {
        return createType;
    }

    public byte[] getPrivateKeyBytes33() {
        return privateKeyBytes33;
    }

    public void setCreateType(int createType) {
        this.createType = createType;
    }

    public long getCreateTime() {
        return createTime;
    }

    public void setCreateTime(long createTime) {
        this.createTime = createTime;
    }

    public boolean isWatchOnly() {
        return isWatchOnly;
    }

    public boolean isWatchCold() {
        return isWatchOnly && getCreateType() == Parameter.CreateWalletType.TYPE_IMPORT_COLD;
    }

    public boolean isWatchNotPaired() {
        return isWatchOnly
                && getCreateType() != Parameter.CreateWalletType.TYPE_IMPORT_LEDGER
                && getCreateType() != Parameter.CreateWalletType.TYPE_IMPORT_COLD
                && getCreateType() != Parameter.CreateWalletType.TYPE_IMPORT_SAMSUNG_HD;
    }

    public void setWatchOnly(boolean watchOnly) {
        isWatchOnly = watchOnly;
    }

    public String getWalletName() {
        return walletName;
    }

    public void setWalletName(String walletName) {
        this.walletName = walletName;
    }

    public String getEncryptedPassword() {
        return encPassword;
    }

    public void setEncryptedPassword(String password) {
        this.encPassword = password;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getAddress() {
        ECKey key = mECKey;
        if (key != null && AddressUtil.isEmpty(address)) {
            return AddressUtil.encode58Check(key.getAddress());
        } else if (publicKey != null && AddressUtil.isEmpty(address)) {
            return AddressUtil.encode58Check(ECKey.fromPublicOnly(publicKey).getAddress());
        } else {
            return address;
        }
    }

    public byte[] getDecode58CheckAddress() {
        ECKey key = mECKey;
        if (key != null && AddressUtil.isEmpty(address)) {
            return key.getAddress();
        } else if (publicKey != null && AddressUtil.isEmpty(address)) {
            return ECKey.fromPublicOnly(publicKey).getAddress();
        } else {
            return AddressUtil.decode58Check(address);
        }
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public ECKey getECKey() {
        return mECKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encPrivateKey;
    }

    public void setEncryptedPrivateKey(byte[] encPrivateKey) {
        this.encPrivateKey = encPrivateKey;
    }

    /**
     * @param master
     * @param purpose      default44 (Documentation source from   BIP43)
     * @param coinType     TRON default 195
     * @param account      default 0
     * @param change       default 0
     * @param accountIndex default 0
     */
    public Bip32ECKeyPair generateBip44KeyPair(Bip32ECKeyPair master, int purpose, int coinType, int account, int change, int accountIndex) {
        WalletPath.validate(purpose, coinType, account, change, accountIndex);
        // m/44'/60'/0'/0
        // m/44'/195'/0'/0/0
        final int[] path = {purpose | HARDENED_BIT, coinType | HARDENED_BIT, account | HARDENED_BIT, change, accountIndex};

        return Bip32ECKeyPair.deriveKeyPair(master, path);
    }

    public Bip32ECKeyPair generateBip44KeyPair(Bip32ECKeyPair master) {
        return generateBip44KeyPair(master, 44, 195, 0, 0, 0);
    }

    @Override
    public int compareTo(@NonNull Wallet o) {

        if (this.createTime == o.getCreateTime()) {
            return 0;
        } else if (this.createTime > o.getCreateTime()) {
            return 1;
        } else {
            return -1;

        }
    }

    //    ================ START: merge Samsung keystore sdk ==============================
    private boolean isSamsungWallet = false;

    public boolean isSamsungWallet() {
        return createType == Parameter.CreateWalletType.TYPE_IMPORT_SAMSUNG_HD;
    }

    public boolean isLedgerHDWallet() {
        return createType == Parameter.CreateWalletType.TYPE_IMPORT_LEDGER;
    }

    public void setSamsungWallet(boolean samsungWallet) {
        isSamsungWallet = samsungWallet;
    }

    private String seedHash;


    public String getSeedHash() {
        return seedHash;
    }

    public void setSeedHash(String seedHash) {
        this.seedHash = seedHash;
    }

    //    ================= END =============================

    public synchronized void clearSensitiveData() {
        SensitiveData.clear(mnemonicChars);
        mnemonicChars = null;
        if (privateKeyBytes33 != null) {
            clearByteArray(privateKeyBytes33);
            privateKeyBytes33 = null;
        }

        if (encPrivateKey != null) {
            clearByteArray(encPrivateKey);
            encPrivateKey = null;
        }

        if (mECKey != null) {
            // Public metadata remains usable after releasing the signing-key reference.
            if (publicKey == null) publicKey = mECKey.getPubKey();
            if (AddressUtil.isEmpty(address)) address = AddressUtil.encode58Check(mECKey.getAddress());
            mECKey = null;
        }
        keyStore = null;
    }

    private void clearByteArray(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

}
