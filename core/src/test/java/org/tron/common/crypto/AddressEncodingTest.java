package org.tron.common.crypto;

import com.google.gson.Gson;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.datatypes.Address;
import org.tron.common.utils.abi.AbiUtil;
import org.tron.walletserver.AddressUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** JAVA-06: address representations must preserve the same 20-byte identity. */
public class AddressEncodingTest {
    private static final String LEADING_41 = "41ababababababababababababababababababab";
    private static final List<String> PAYLOADS = List.of(
            LEADING_41,
            "70c77e8ac165d2980e9741cb4af2e40cf3c280de",
            "0000000000000000000000000000000000000010");

    private static List<String> forms(String payload) {
        return List.of(payload, "0x" + payload, "41" + payload, "0x41" + payload,
                "0X" + payload, "0X41" + payload, payload.toUpperCase(Locale.ROOT),
                AddressUtil.encode58Check(Hex.decode("41" + payload)));
    }

    private static byte[] word(String payload) {
        byte[] result = new byte[32];
        byte[] raw = Hex.decode(payload);
        System.arraycopy(raw, 0, result, result.length - raw.length, raw.length);
        return result;
    }

    private static byte[] hash(byte[]... parts) {
        Keccak.Digest256 digest = new Keccak.Digest256();
        for (byte[] part : parts) {
            digest.update(part, 0, part.length);
        }
        return digest.digest();
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static StructuredDataEncoder encoder(String type, Object recipient,
                                                  String verifyingContract) throws Exception {
        String json = new Gson().toJson(Map.of(
                "types", Map.of(
                        "EIP712Domain", List.of(
                                Map.of("name", "name", "type", "string"),
                                Map.of("name", "verifyingContract", "type", "address")),
                        "Envelope", List.of(Map.of("name", "recipient", "type", type))),
                "primaryType", "Envelope",
                "domain", Map.of("name", "Address encoding",
                        "verifyingContract", verifyingContract),
                "message", Map.of("recipient", recipient)));
        return new StructuredDataEncoder(json);
    }

    // Independent oracle: the expected payload is never parsed by Address or AbiUtil.
    private static byte[] referenceDomain(String payload) {
        return hash(hash(utf8("EIP712Domain(string name,address verifyingContract)")),
                hash(utf8("Address encoding")), word(payload));
    }

    private static byte[] referenceDigest(String type, byte[] encodedRecipient, String payload) {
        byte[] message = hash(hash(utf8("Envelope(" + type + " recipient)")), encodedRecipient);
        return hash(new byte[] {0x19, 0x01}, referenceDomain(payload), message);
    }

    @Test
    public void normalization_preservesPayloadForEverySupportedForm() {
        for (String payload : PAYLOADS) {
            for (String input : forms(payload)) {
                String normalized = AddressUtil.replace41Address(input);
                Assert.assertEquals(input, payload, normalized.toLowerCase(Locale.ROOT));
                Assert.assertEquals(input, normalized, AddressUtil.replace41Address(normalized));
            }
        }
    }

    @Test
    public void shortHex_preservesLeading41ForUint160Compatibility() {
        Assert.assertEquals(BigInteger.valueOf(0x41), new Address("41").toUint().getValue());
        Assert.assertEquals(BigInteger.valueOf(0x41ab), new Address("41ab").toUint().getValue());
    }

    @Test
    public void abiAddressConstructors_preserveFullAddressWord() {
        for (String payload : PAYLOADS) {
            String expected = Hex.toHexString(word(payload));
            for (String input : forms(payload)) {
                Assert.assertEquals(input, expected, TypeEncoder.encode(new Address(input)));
                Assert.assertEquals(input, expected, TypeEncoder.encode(new Address(input, true)));
            }
            Assert.assertEquals(expected, TypeEncoder.encode(new Address(payload, false)));
        }
    }

    @Test
    public void abiInputEncoding_preservesFullAddressWord() {
        for (String payload : PAYLOADS) {
            for (String input : forms(payload)) {
                Assert.assertArrayEquals(input, word(payload),
                        AbiUtil.encodeInput("initialize(address)", input));
                Assert.assertArrayEquals(input, word(payload),
                        AbiUtil.encodeInputFromList("initialize(address)", List.of(input)));
            }
        }
    }

    @Test
    public void typedDataScalar_matchesIndependentDigest() throws Exception {
        for (String payload : PAYLOADS) {
            byte[] expected = referenceDigest("address", word(payload), payload);
            for (String input : forms(payload)) {
                Assert.assertArrayEquals(input, expected,
                        encoder("address", input, "0x" + payload).hashStructuredData());
            }
        }
    }

    @Test
    public void typedDataVerifyingContract_matchesIndependentDomain() throws Exception {
        for (String payload : PAYLOADS) {
            for (String input : forms(payload)) {
                Assert.assertArrayEquals(input, referenceDomain(payload),
                        encoder("address", "0x" + payload, input).hashDomain());
            }
        }
    }

    @Test
    public void typedDataAddressArrays_preserveFullAddressWord() throws Exception {
        // Alphanumeric payloads isolate prefix handling from legacy numeric-array parsing.
        for (String payload : PAYLOADS.subList(0, 2)) {
            for (String input : forms(payload)) {
                for (String type : List.of("address[]", "address[1]")) {
                    Assert.assertArrayEquals(type + ": " + input,
                            referenceDigest(type, hash(word(payload)), payload),
                            encoder(type, List.of(input), "0x" + payload).hashStructuredData());
                }
            }
        }
    }

    @Test
    public void typedDataNestedAddressArrays_matchDigestAndDisplayClassification() throws Exception {
        for (String payload : PAYLOADS) {
            String tronHex = "41" + payload;
            StructuredDataEncoder encoder = encoder("address[][]", List.of(
                    List.of(tronHex, payload),
                    List.of(),
                    List.of("0x" + tronHex, "0X" + tronHex,
                            AddressUtil.encode58Check(Hex.decode(tronHex)))), "0x" + payload);
            byte[] encodedArray = hash(
                    hash(word(payload), word(payload)),
                    hash(),
                    hash(word(payload), word(payload), word(payload)));

            Assert.assertArrayEquals(referenceDigest("address[][]", encodedArray, payload),
                    encoder.hashStructuredData());
            Assert.assertEquals(List.of(tronHex, "0x" + tronHex, "0X" + tronHex),
                    encoder.getParseAddressList());
        }
    }

    @Test
    public void signature_authorizesIntendedRecipientInsteadOfTruncatedAddress() throws Exception {
        ECKey key = ECKey.fromPrivate(BigInteger.ONE); // Public test key, used only locally.
        String truncated = "00" + LEADING_41.substring(2);
        byte[] expected = referenceDigest("address", word(LEADING_41), LEADING_41);
        byte[] wrong = referenceDigest("address", word(truncated), LEADING_41);

        for (String input : forms(LEADING_41)) {
            ECKey.ECDSASignature signature = key.sign(
                    encoder("address", input, "0x" + LEADING_41).hashStructuredData());
            Assert.assertTrue(input, key.verify(expected, signature));
            Assert.assertFalse(input, key.verify(wrong, signature));
        }
    }
}
