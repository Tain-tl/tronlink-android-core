package org.tron.common.crypto;

import com.google.gson.Gson;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.walletserver.AddressUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Regression coverage for S-01: address array elements must always use hexadecimal. */
public class StructuredDataEncoderAddressArrayTest {

    private static final String ADDRESS_16 = "0000000000000000000000000000000000000010";
    private static final String ADDRESS_10 = "000000000000000000000000000000000000000a";

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

    private static byte[] word(byte[] value) {
        byte[] result = new byte[32];
        System.arraycopy(value, 0, result, result.length - value.length, value.length);
        return result;
    }

    // Independent EIP-712 oracle: no production Address, TypeEncoder or Hash helpers.
    private static byte[] referenceDigest(String arrayType, byte[] arrayHash) {
        byte[] domainHash = hash(
                hash(utf8("EIP712Domain(string name,uint256 chainId)")),
                hash(utf8("Address Audit")),
                word(BigInteger.valueOf(728126428).toByteArray()));
        byte[] messageHash = hash(
                hash(utf8("Envelope(" + arrayType + " destinations)")), arrayHash);
        return hash(new byte[] {0x19, 0x01}, domainHash, messageHash);
    }

    private static byte[] actualDigest(String arrayType, List<?> destinations) throws Exception {
        String json = new Gson().toJson(Map.of(
                "types", Map.of(
                        "EIP712Domain", List.of(
                                Map.of("name", "name", "type", "string"),
                                Map.of("name", "chainId", "type", "uint256")),
                        "Envelope", List.of(
                                Map.of("name", "destinations", "type", arrayType))),
                "primaryType", "Envelope",
                "domain", Map.of("name", "Address Audit", "chainId", 728126428),
                "message", Map.of("destinations", destinations)));
        return new StructuredDataEncoder(json).hashStructuredData();
    }

    private static String base58(String payload) {
        return AddressUtil.encode58Check(Hex.decode("41" + payload));
    }

    @Test
    public void numericOnlyAddress_doesNotCollideWithDecimalEquivalent() throws Exception {
        byte[] actual16 = actualDigest("address[]", List.of("0x" + ADDRESS_16));
        byte[] actual10 = actualDigest("address[]", List.of("0x" + ADDRESS_10));

        Assert.assertFalse("Distinct addresses must have distinct digests",
                Arrays.equals(actual16, actual10));
        Assert.assertArrayEquals(referenceDigest("address[]", hash(word(Hex.decode(ADDRESS_16)))),
                actual16);
        Assert.assertArrayEquals(referenceDigest("address[]", hash(word(Hex.decode(ADDRESS_10)))),
                actual10);
    }

    @Test
    public void mainnetDomainSignature_verifiesOnlyForIntendedAddress() throws Exception {
        // Public test private key 1; no production wallet or network is involved.
        ECKey key = ECKey.fromPrivate(BigInteger.ONE);
        ECKey.ECDSASignature signature =
                key.sign(actualDigest("address[]", List.of("0x" + ADDRESS_16)));

        Assert.assertTrue(key.verify(
                referenceDigest("address[]", hash(word(Hex.decode(ADDRESS_16)))), signature));
        Assert.assertFalse(key.verify(
                referenceDigest("address[]", hash(word(Hex.decode(ADDRESS_10)))), signature));
    }

    @Test
    public void supportedAddressFormats_matchSameHexadecimalWord() throws Exception {
        byte[] expected = referenceDigest("address[]", hash(word(Hex.decode(ADDRESS_16))));
        for (String address : List.of(
                ADDRESS_16, "0x" + ADDRESS_16, "41" + ADDRESS_16, base58(ADDRESS_16))) {
            Assert.assertArrayEquals(address, expected, actualDigest("address[]", List.of(address)));
        }
    }

    @Test
    public void payloadStartingWith41_isNotNormalizedTwice() throws Exception {
        String payload = "4100000000000000000000000000000000000010";
        byte[] expected = referenceDigest("address[]", hash(word(Hex.decode(payload))));
        for (String address : List.of("0x" + payload, "41" + payload, base58(payload))) {
            Assert.assertArrayEquals(address, expected, actualDigest("address[]", List.of(address)));
        }
    }

    @Test
    public void fixedAndDynamicArrays_matchIndependentWordEncoding() throws Exception {
        List<String> addresses = List.of("0x" + ADDRESS_16, "0x" + ADDRESS_10);
        byte[] arrayHash = hash(word(Hex.decode(ADDRESS_16)), word(Hex.decode(ADDRESS_10)));
        for (String type : List.of("address[]", "address[2]")) {
            Assert.assertArrayEquals(referenceDigest(type, arrayHash), actualDigest(type, addresses));
        }
    }

    @Test
    public void nestedArrays_preserveWordEncodingAndArrayBoundaries() throws Exception {
        byte[] row16 = hash(word(Hex.decode(ADDRESS_16)));
        byte[] row10 = hash(word(Hex.decode(ADDRESS_10)));
        List<List<String>> rows = List.of(
                List.of("0x" + ADDRESS_16), List.of(base58(ADDRESS_10)));
        for (String type : List.of("address[][]", "address[1][2]")) {
            Assert.assertArrayEquals(referenceDigest(type, hash(row16, row10)),
                    actualDigest(type, rows));
        }

        Assert.assertArrayEquals(referenceDigest("address[][2]", hash(hash(), row16)),
                actualDigest("address[][2]", List.of(List.of(), List.of("41" + ADDRESS_16))));
    }

    @Test
    public void valuesOutsideUint160Range_areRejected() throws Exception {
        for (String address : List.of("-1", "0x010000000000000000000000000000000000000000")) {
            try {
                actualDigest("address[]", List.of(address));
                Assert.fail("Expected invalid uint160 address to be rejected: " + address);
            } catch (IllegalArgumentException expected) {
                Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("address"));
            }
        }
    }
}
