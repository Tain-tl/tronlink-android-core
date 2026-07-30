package org.tron.common.utils;

import org.junit.Assert;
import org.junit.Test;
import org.tron.walletserver.TriggerData;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

public class TriggerLoadArrayTest {

    @Test
    public void uintArray_isReturnedAsOneConfirmationParameter() {
        byte[] data = concat(word(32), word(2), word(7), word(9));

        Map<String, String> parsed = TriggerLoad.parseTriggerDataByFun(data, "set(uint256[])");

        Assert.assertEquals(1, parsed.size());
        Assert.assertEquals("[7, 9]", parsed.get("0"));

        TriggerData triggerData = new TriggerData();
        triggerData.setMethod("set(uint256[])");
        triggerData.setParameterMap(parsed);
        Assert.assertEquals(1, triggerData.parseDataForTypeValueList().size());
        Assert.assertEquals("[7, 9]",
                triggerData.parseDataForTypeValueList().get(0).getValue());
    }

    @Test
    public void emptyArray_isDisplayedExplicitly() {
        Map<String, String> parsed =
                TriggerLoad.parseTriggerDataByFun(concat(word(32), word(0)), "set(address[])");

        Assert.assertEquals("[]", parsed.get("0"));
    }

    @Test
    public void stringArray_decodesElementOffsets() {
        byte[] first = padded("abc");
        byte[] second = padded("d");
        byte[] data = concat(
                word(32), word(2), word(64), word(128),
                word(3), first, word(1), second);

        Map<String, String> parsed = TriggerLoad.parseTriggerDataByFun(data, "set(string[])");

        Assert.assertEquals("[\"abc\", \"d\"]", parsed.get("0"));
    }

    @Test
    public void addressArray_convertsElementsToTronAddresses() {
        byte[] evmAddress = new byte[20];
        evmAddress[19] = 1;
        byte[] addressWord = new byte[32];
        System.arraycopy(evmAddress, 0, addressWord, 12, evmAddress.length);
        byte[] tronAddress = new byte[21];
        tronAddress[0] = 0x41;
        System.arraycopy(evmAddress, 0, tronAddress, 1, evmAddress.length);

        Map<String, String> parsed = TriggerLoad.parseTriggerDataByFun(
                concat(word(32), word(1), addressWord), "set(address[])");

        Assert.assertEquals(
                "[" + org.tron.walletserver.AddressUtil.encode58Check(tronAddress) + "]",
                parsed.get("0"));
    }

    @Test
    public void malformedArrayOffset_returnsEmptyWithoutCrashingCaller() {
        Assert.assertTrue(TriggerLoad.parseTriggerDataByFun(
                concat(word(64), word(1), word(7)), "set(uint256[])").isEmpty());
    }

    @Test
    public void truncatedArray_returnsEmptyWithoutCrashingCaller() {
        Assert.assertTrue(TriggerLoad.parseTriggerDataByFun(
                concat(word(32), word(2), word(7)), "set(uint256[])").isEmpty());
    }

    @Test
    public void nestedArray_returnsEmptyWithoutCrashingCaller() {
        Assert.assertTrue(TriggerLoad.parseTriggerDataByFun(
                concat(word(32), word(0)), "set(uint256[][])").isEmpty());
    }

    @Test
    public void missingArrayData_returnsEmptyWithoutCrashingCaller() {
        Assert.assertTrue(
                TriggerLoad.parseTriggerDataByFun(new byte[0], "set(uint256[])").isEmpty());
    }

    private static byte[] word(long value) {
        byte[] encoded = new byte[32];
        byte[] raw = BigInteger.valueOf(value).toByteArray();
        System.arraycopy(raw, 0, encoded, encoded.length - raw.length, raw.length);
        return encoded;
    }

    private static byte[] padded(String value) {
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(raw, ((raw.length + 31) / 32) * 32);
    }

    private static byte[] concat(byte[]... values) {
        int length = 0;
        for (byte[] value : values) {
            length += value.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }
}
