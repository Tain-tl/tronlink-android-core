package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;

public class WalletMnemonicValidationTest {

    private static final String VALID_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon about";
    private static final String UNKNOWN_WORD_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon tronlink";
    private static final String INVALID_CHECKSUM_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon abandon";

    @Test
    public void mnemonicImport_acceptsValidBip39Mnemonic() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC, VALID_MNEMONIC);

        Assert.assertTrue(wallet.isOpen());
    }

    @Test
    public void mnemonicImport_rejectsWordOutsideEnglishWordList() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC, UNKNOWN_WORD_MNEMONIC);

        Assert.assertFalse(wallet.isOpen());
    }

    @Test
    public void mnemonicImport_rejectsInvalidBip39Checksum() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC, INVALID_CHECKSUM_MNEMONIC);

        Assert.assertFalse(wallet.isOpen());
    }

    @Test
    public void customPathMnemonicImport_usesSameValidation() {
        Wallet wallet = new Wallet(UNKNOWN_WORD_MNEMONIC, WalletPath.createDefault());

        Assert.assertFalse(wallet.isOpen());
        Assert.assertNull(wallet.getMnemonic());
    }
}
