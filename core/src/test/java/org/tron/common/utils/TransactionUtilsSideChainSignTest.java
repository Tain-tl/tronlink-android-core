package org.tron.common.utils;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.protos.Protocol;
import org.tron.protos.contract.BalanceContract;

public class TransactionUtilsSideChainSignTest {

    @Test
    public void sign_sideChain_rejectsNullChainId() {
        try {
            TransactionUtils.sign(createTransferTransaction(), new ECKey(), null, false);
            Assert.fail("expected IllegalArgumentException for null chainId");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void sign_sideChain_rejectsEmptyChainId() {
        // ChainBean coerces a missing chainId to "" and ByteArray.fromHexString("")
        // yields byte[0], so the production path delivers empty, never null.
        try {
            TransactionUtils.sign(createTransferTransaction(), new ECKey(), new byte[0], false);
            Assert.fail("expected IllegalArgumentException for empty chainId");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void sign_sideChain_acceptsNonEmptyChainId() {
        byte[] chainId = Sha256Hash.hash(new byte[]{1});

        Protocol.Transaction signed =
                TransactionUtils.sign(createTransferTransaction(), new ECKey(), chainId, false);

        Assert.assertEquals(1, signed.getSignatureCount());
        Assert.assertFalse(signed.getSignature(0).isEmpty());
    }

    @Test
    public void sign_mainChain_ignoresChainId() {
        Protocol.Transaction signed =
                TransactionUtils.sign(createTransferTransaction(), new ECKey(), null, true);

        Assert.assertEquals(1, signed.getSignatureCount());
        Assert.assertFalse(signed.getSignature(0).isEmpty());
    }

    private static Protocol.Transaction createTransferTransaction() {
        byte[] owner = Hex.decode("41a0abd659056697b68feeed0d4bcab3752c01a0f9");
        byte[] to = Hex.decode("41b0abd659056697b68feeed0d4bcab3752c01a0fa");

        BalanceContract.TransferContract transfer = BalanceContract.TransferContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(owner))
                .setToAddress(ByteString.copyFrom(to))
                .setAmount(1000000L)
                .build();

        Protocol.Transaction.Contract contract = Protocol.Transaction.Contract.newBuilder()
                .setType(Protocol.Transaction.Contract.ContractType.TransferContract)
                .setParameter(Any.pack(transfer))
                .build();

        Protocol.Transaction.raw raw = Protocol.Transaction.raw.newBuilder()
                .setRefBlockBytes(ByteString.copyFrom(Hex.decode("0001")))
                .setRefBlockHash(ByteString.copyFrom(Hex.decode("1122334455667788")))
                .setExpiration(1710000000000L)
                .setTimestamp(1709999940000L)
                .addContract(contract)
                .build();

        return Protocol.Transaction.newBuilder()
                .setRawData(raw)
                .build();
    }
}
