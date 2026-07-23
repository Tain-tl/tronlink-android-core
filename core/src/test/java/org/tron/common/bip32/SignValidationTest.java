package org.tron.common.bip32;

import org.junit.Test;

import java.math.BigInteger;

public class SignValidationTest {

    @Test(expected = IllegalArgumentException.class)
    public void verifyPrecondition_failure_throwsIllegalArgumentException() {
        Assertions.verifyPrecondition(false, "invalid input");
    }

    @Test(expected = IllegalArgumentException.class)
    public void signMessage_mismatchedPublicKey_throwsIllegalArgumentException() {
        ECKeyPair mismatchedKeyPair = new ECKeyPair(BigInteger.ONE, BigInteger.ZERO);

        Sign.signMessage(new byte[32], mismatchedKeyPair, false);
    }
}
