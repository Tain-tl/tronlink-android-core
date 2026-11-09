package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.bip32.Numeric;

import java.util.Arrays;
import java.util.Map;

/** Regression coverage for TronWeb-compatible recursive EIP/TIP-712 array hashing. */
public class StructuredDataEncoderMultidimensionalArrayTest {

    private static String arrayJson(String type, String value) {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[],"
                + "\"Payload\":[{\"name\":\"items\",\"type\":\"" + type + "\"}]"
                + "},"
                + "\"primaryType\":\"Payload\","
                + "\"domain\":{},"
                + "\"message\":{\"items\":" + value + "}"
                + "}";
    }

    @SuppressWarnings("unchecked")
    private static byte[] arrayFieldHash(String json) throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(json);
        byte[] encoded =
                encoder.encodeData("Payload", (Map<String, Object>) encoder.getMessage());
        return Arrays.copyOfRange(encoded, 32, 64);
    }

    private static void assertFieldHash(String expected, String type, String value)
            throws Exception {
        Assert.assertEquals(expected, Numeric.toHexString(arrayFieldHash(arrayJson(type, value))));
    }

    @Test
    public void dynamicUint256TwoDimensionalArray_matchesTronWebVector() throws Exception {
        assertFieldHash(
                "0x44f4c336be0c608b809d9eab4b03a1457b1c7911b7a93e76c754acc1aea7eb9c",
                "uint256[][]",
                "[[1,2],[3,4],[5,6]]");
    }

    @Test
    public void multidimensionalArrayHash_preservesNestingBoundaries() throws Exception {
        byte[] twoRows =
                arrayFieldHash(arrayJson("uint256[][]", "[[1,2,3],[4,5,6]]"));
        byte[] threeRows =
                arrayFieldHash(arrayJson("uint256[][]", "[[1,2],[3,4],[5,6]]"));

        Assert.assertFalse(Arrays.equals(twoRows, threeRows));
    }

    @Test
    public void fixedDimensions_followSoliditySuffixOrder() throws Exception {
        assertFieldHash(
                "0x44f4c336be0c608b809d9eab4b03a1457b1c7911b7a93e76c754acc1aea7eb9c",
                "uint256[2][3]",
                "[[1,2],[3,4],[5,6]]");
    }

    @Test
    public void mixedFixedOuterAndDynamicInner_acceptsRaggedAndEmptyArrays() throws Exception {
        assertFieldHash(
                "0xde336a9bdae55162dafa8cf16d0ade93d82ab6ecf99d4bc18f71d0a1f3d4242a",
                "uint256[][2]",
                "[[],[1,2,3]]");
    }

    @Test
    public void fixedInnerDimension_isValidatedForEveryElement() throws Exception {
        try {
            arrayFieldHash(arrayJson("uint256[2][]", "[[1,2],[3]]"));
            Assert.fail("Expected the second uint256[2] value to be rejected");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("uint256[2]"));
        }
    }

    @Test
    public void nestedDynamicTypes_hashAtEveryArrayLevel() throws Exception {
        assertFieldHash(
                "0x8319b05ea5c4f619545b1003de94ef7251d201f3def8fc48a6c7267fa6bdda52",
                "string[][]",
                "[[\"one\",\"two\"],[]]");
        assertFieldHash(
                "0x8538e99138397dddf32224ede38097c4eff5842d8d6ae808d7e306ef6955dfdd",
                "bytes32[][]",
                "[[\"0x1111111111111111111111111111111111111111111111111111111111111111\"],[]]");
        assertFieldHash(
                "0xe0e82c9c04ccb826eee74db204a210b57a0d83c84d014d9bc4dfd2ae5882b92d",
                "trcToken[][]",
                "[[1,2],[]]");
    }

    @Test
    public void tronBase58AddressTwoDimensionalArray_isSupported() throws Exception {
        assertFieldHash(
                "0xf8bf1e20304e473ecf9e1c9b3887a9aa14a5a254b0e704c97c7e1012a46c5e83",
                "address[][]",
                "[[\"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH\"],"
                        + "[\"TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7\"]]");
    }

    @Test
    public void customStructTwoDimensionalArray_isSupported() throws Exception {
        String json = "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[],"
                + "\"Payload\":[{\"name\":\"items\",\"type\":\"Person[][]\"}],"
                + "\"Person\":[{\"name\":\"name\",\"type\":\"string\"}]"
                + "},"
                + "\"primaryType\":\"Payload\","
                + "\"domain\":{},"
                + "\"message\":{\"items\":[[{\"name\":\"Alice\"}],[],"
                + "[{\"name\":\"Bob\"},{\"name\":\"Carol\"}]]}"
                + "}";

        Assert.assertEquals(
                "0x4587a833bd09149b18461714c762f738ffa3e7e853686f7c3d27a4fa56bb517d",
                Numeric.toHexString(arrayFieldHash(json)));
    }
}
