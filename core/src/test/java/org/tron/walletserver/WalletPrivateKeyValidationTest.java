package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;

import java.math.BigInteger;

public class WalletPrivateKeyValidationTest {

    @Test
    public void privateKeyImport_acceptsSecp256k1Boundaries() {
        Assert.assertTrue(importPrivateKey(BigInteger.ONE).isOpen());
        Assert.assertTrue(importPrivateKey(ECKey.CURVE.getN().subtract(BigInteger.ONE)).isOpen());
    }

    @Test
    public void privateKeyImport_rejectsValuesOutsideSecp256k1Range() {
        Assert.assertFalse(importPrivateKey(BigInteger.ZERO).isOpen());
        Assert.assertFalse(importPrivateKey(ECKey.CURVE.getN()).isOpen());
        Assert.assertFalse(importPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE)).isOpen());
    }

    @Test
    public void privateKeyImport_doesNotTreatOneAndNPlusOneAsAliases() {
        Wallet validWallet = importPrivateKey(BigInteger.ONE);
        Wallet outOfRangeWallet = importPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE));

        Assert.assertTrue(validWallet.isOpen());
        Assert.assertFalse(outOfRangeWallet.isOpen());
    }

    @Test
    public void privateKeyImport_requiresCanonical32ByteEncoding() {
        Assert.assertFalse(new Wallet(I_TYPE.PRIVATE, "1").isOpen());
        Assert.assertFalse(new Wallet(I_TYPE.PRIVATE, "001").isOpen());
        Assert.assertFalse(new Wallet(I_TYPE.PRIVATE,
                "0" + String.format("%064x", BigInteger.ONE)).isOpen());
        Assert.assertTrue(new Wallet(I_TYPE.PRIVATE,
                "0x" + String.format("%064x", BigInteger.ONE)).isOpen());
    }

    @Test
    public void privateKeyImport_keepsExportAddressAndSigningKeyConsistent() {
        for (BigInteger value : new BigInteger[]{BigInteger.ONE, ECKey.CURVE.getN().subtract(BigInteger.ONE)}) {
            Wallet wallet = new Wallet(I_TYPE.PRIVATE, "0X" + String.format("%064x", value));
            ECKey expected = ECKey.fromPrivate(value);

            Assert.assertTrue(wallet.isOpen());
            Assert.assertArrayEquals(expected.getPrivKeyBytes(), wallet.getPrivateKey());
            Assert.assertArrayEquals(expected.getPrivKeyBytes(), wallet.getPrivateKeyBytes33());
            Assert.assertArrayEquals(expected.getPubKey(), wallet.getPublicKey());
            Assert.assertArrayEquals(expected.getAddress(), wallet.getDecode58CheckAddress());
            Assert.assertEquals(AddressUtil.encode58Check(expected.getAddress()), wallet.getAddress());

            byte[] digest = new byte[32];
            digest[0] = 42;
            Assert.assertTrue(expected.verify(digest, wallet.getECKey().doSign(digest)));
        }
    }

    @Test
    public void privateKeyImport_invalidInputDoesNotRetainKeyMaterial() {
        for (String input : new String[]{null, "", "not-hex", "1",
                String.format("%064x", BigInteger.ZERO),
                String.format("%064x", ECKey.CURVE.getN())}) {
            Wallet wallet = new Wallet(I_TYPE.PRIVATE, input);

            Assert.assertFalse(wallet.isOpen());
            Assert.assertNull(wallet.getECKey());
            Assert.assertNull(wallet.getPrivateKey());
            Assert.assertNull(wallet.getPrivateKeyBytes33());
            Assert.assertNull(wallet.getPublicKey());
            Assert.assertEquals("", wallet.getAddress());
        }
    }

    private static Wallet importPrivateKey(BigInteger privateKey) {
        return new Wallet(I_TYPE.PRIVATE, String.format("%064x", privateKey));
    }
}
