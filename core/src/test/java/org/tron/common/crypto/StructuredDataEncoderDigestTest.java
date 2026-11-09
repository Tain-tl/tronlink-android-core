package org.tron.common.crypto;

import org.junit.Test;
import org.tron.common.bip32.Numeric;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class StructuredDataEncoderDigestTest {

    private static StructuredDataEncoder bytesArrayEncoder(String items) throws IOException {
        return new StructuredDataEncoder("""
                {
                  "types": {
                    "EIP712Domain": [{"name":"name","type":"string"}],
                    "Payload": [{"name":"items","type":"bytes[][]"}]
                  },
                  "primaryType": "Payload",
                  "domain": {"name":"Test"},
                  "message": {"items":%s}
                }
                """.formatted(items));
    }

    private static StructuredDataEncoder emptyStructEncoder() throws IOException {
        return new StructuredDataEncoder("""
                {
                  "types": {"EIP712Domain": [], "Empty": []},
                  "primaryType": "Empty",
                  "domain": {},
                  "message": {}
                }
                """);
    }

    // Reference vectors computed directly from EIP-712's Keccak-256 and concatenation rules.
    @Test
    public void differentBytesArrayGroupings_matchDistinctSigningDigests() throws Exception {
        assertEquals("0xc90ddac493f89a38e6bd5ee89ddcd5cac492eae5be8adc75a5c156d17016068a",
                Numeric.toHexString(bytesArrayEncoder("[[\"0x01\",\"0x02\"],[\"0x03\",\"0x04\"]]")
                        .hashStructuredData()));
        assertEquals("0x1b226482bcbd66c5fd8dfa615a71ce5d6e70862be36a02ede9cac3c7453c2f1f",
                Numeric.toHexString(bytesArrayEncoder("[[\"0x01\"],[\"0x02\"],[\"0x03\"],[\"0x04\"]]")
                        .hashStructuredData()));
    }

    @Test
    public void bytesArrayWithEmptyChild_matchesSigningDigest() throws Exception {
        assertEquals("0xf555df2b0085c5a7ca78742e600381cb7e8a0efa5c0dd4f0f937433ff5d69816",
                Numeric.toHexString(bytesArrayEncoder("[[\"0x01\"],[]]").hashStructuredData()));
    }

    @Test
    public void emptyDomain_matchesTypeHashAndDomainSeparator() throws Exception {
        StructuredDataEncoder encoder = emptyStructEncoder();

        assertEquals("EIP712Domain()", encoder.encodeType("EIP712Domain"));
        assertEquals("0x20bcc3f8105eea47d067386e42e60246e89393cd61c512edd1e87688890fb914",
                Numeric.toHexString(encoder.typeHash("EIP712Domain")));
        assertEquals("0x6192106f129ce05c9075d319c1fa6ea9b3ae37cbd0c1ef92e2be7137bb07baa1",
                Numeric.toHexString(encoder.hashDomain()));
    }

    @Test
    public void namedDomain_matchesDomainSeparator() throws Exception {
        assertEquals("0x19175c8f4872b78bf0fdb9dcd005000a0f2d4939399efcfe595eed450de2281c",
                Numeric.toHexString(bytesArrayEncoder("[]").hashDomain()));
    }

    @Test
    public void emptyMessage_matchesStructHashAndSigningDigest() throws Exception {
        StructuredDataEncoder encoder = emptyStructEncoder();

        assertEquals("Empty()", encoder.encodeType("Empty"));
        assertEquals("0xd0c9221139d8bc1ad93339974972c312c9a1cd07c8ec56131879b77cf140602b",
                Numeric.toHexString(encoder.hashMessage()));
        assertEquals("0xfed1151c69fd0f6ace56fa35f35380cf01d77d74a538056ab2b013bb0b838f25",
                Numeric.toHexString(encoder.hashStructuredData()));
    }
}
