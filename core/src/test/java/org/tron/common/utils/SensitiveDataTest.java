package org.tron.common.utils;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class SensitiveDataTest {
    @Test
    public void nullAndEmptyConversionsPreserveTheirMeanings() {
        Assert.assertNull(SensitiveData.toUtf8Bytes(null));
        Assert.assertNull(SensitiveData.fromUtf8Bytes(null));
        Assert.assertArrayEquals(new byte[0], SensitiveData.toUtf8Bytes(new char[0]));
        Assert.assertArrayEquals(new char[0], SensitiveData.fromUtf8Bytes(new byte[0]));
        SensitiveData.clear((byte[]) null);
        SensitiveData.clear((char[]) null);
    }

    @Test
    public void encodingMatchesLegacyUtf8IncludingMalformedSurrogates() {
        String[] examples = {"ASCII mnemonic", "café 钱包", "a\uD83D\uDE00z",
                "\uD800", "\uDC00", "a\uD800b\uDC00", "\uD800\uD800\uDC00"};
        for (String text : examples) {
            Assert.assertArrayEquals(text.getBytes(StandardCharsets.UTF_8),
                    SensitiveData.toUtf8Bytes(text.toCharArray()));
        }
    }

    @Test
    public void decodingMatchesLegacyUtf8Replacement() {
        byte[][] examples = {"café 钱包 \uD83D\uDE00".getBytes(StandardCharsets.UTF_8),
                {(byte) 0x80}, {(byte) 0xc0, (byte) 0xaf}, {(byte) 0xe2, (byte) 0x82},
                {(byte) 0xed, (byte) 0xa0, (byte) 0x80},
                {(byte) 0xf4, (byte) 0x90, (byte) 0x80, (byte) 0x80},
                {(byte) 0xe2, 0x41, (byte) 0xa1}};
        for (byte[] encoded : examples) {
            Assert.assertArrayEquals(new String(encoded, StandardCharsets.UTF_8).toCharArray(),
                    SensitiveData.fromUtf8Bytes(encoded));
        }
    }

    @Test
    public void conversionBorrowsInputsAndReturnsIndependentResults() {
        char[] characters = "secret".toCharArray();
        byte[] encoded = SensitiveData.toUtf8Bytes(characters);
        Assert.assertArrayEquals("secret".toCharArray(), characters);
        char[] decoded = SensitiveData.fromUtf8Bytes(encoded);
        Assert.assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), encoded);
        SensitiveData.clear(characters);
        Assert.assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), encoded);
        SensitiveData.clear(encoded);
        Assert.assertArrayEquals("secret".toCharArray(), decoded);
        SensitiveData.clear(decoded);
        SensitiveData.clear(decoded);
        Assert.assertArrayEquals(new char[6], decoded);
        Assert.assertArrayEquals(new byte[6], encoded);
    }
}
