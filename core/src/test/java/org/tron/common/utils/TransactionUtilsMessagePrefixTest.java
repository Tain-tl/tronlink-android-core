package org.tron.common.utils;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.walletserver.AddressUtil;

import java.nio.charset.StandardCharsets;

public class TransactionUtilsMessagePrefixTest {

    @Test
    public void getMessageHash_internalHexPrefixIsPreserved() {
        Assert.assertFalse(
                java.util.Arrays.equals(
                        TransactionUtils.getMessageHash("pay0x100"),
                        TransactionUtils.getMessageHash("pay100")));
    }

    @Test
    public void getMessageHash_leadingHexPrefixIsStillStripped() {
        Assert.assertArrayEquals(
                TransactionUtils.getMessageHash("deadbeef"),
                TransactionUtils.getMessageHash("0xdeadbeef"));
    }

    @Test
    public void verifyMessage_internalHexPrefixInSignatureIsNotRemoved() {
        ECKey key = new ECKey(
                Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                true);
        String message = "message";
        String signature = TransactionUtils.signMessageV2(
                message.getBytes(StandardCharsets.UTF_8), key);
        String signatureWithoutPrefix = signature.substring(2);
        String signatureWithInternalPrefix =
                signatureWithoutPrefix.substring(0, 10)
                        + "0x"
                        + signatureWithoutPrefix.substring(10);
        String address = AddressUtil.encode58Check(key.getAddress());

        Assert.assertTrue(TransactionUtils.verifyMessage(message, signature, address));
        Assert.assertFalse(
                TransactionUtils.verifyMessage(message, signatureWithInternalPrefix, address));
    }
}
