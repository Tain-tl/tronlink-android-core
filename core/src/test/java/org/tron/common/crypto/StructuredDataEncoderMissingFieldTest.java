package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;

/**
 * Regression tests for S-05 (scan 2026-08-11): a declared EIP-712 field whose
 * value was missing or null used to be silently skipped. The encoding has no
 * per-field placeholder, so Mail(from,to) with {from:1} and {to:1} both encoded
 * to [typeHash, 1] — semantically different messages shared one hash/signature.
 */
public class StructuredDataEncoderMissingFieldTest {

    private static String mailJson(String messageBody) {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Mail\":[{\"name\":\"from\",\"type\":\"uint256\"},"
                + "{\"name\":\"to\",\"type\":\"uint256\"}]"
                + "},"
                + "\"primaryType\":\"Mail\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":" + messageBody
                + "}";
    }

    private static String nestedJson(String innerBody) {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Outer\":[{\"name\":\"inner\",\"type\":\"Inner\"}],"
                + "\"Inner\":[{\"name\":\"a\",\"type\":\"uint256\"},"
                + "{\"name\":\"b\",\"type\":\"uint256\"}]"
                + "},"
                + "\"primaryType\":\"Outer\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"inner\":" + innerBody + "}"
                + "}";
    }

    // Declares a two-field domain but supplies only "name".
    private static String partialDomainJson() {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},"
                + "{\"name\":\"version\",\"type\":\"string\"}],"
                + "\"Mail\":[{\"name\":\"from\",\"type\":\"uint256\"}]"
                + "},"
                + "\"primaryType\":\"Mail\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"from\":1}"
                + "}";
    }

    @Test
    public void completeMessage_hashesSuccessfully() throws Exception {
        byte[] hash = new StructuredDataEncoder(mailJson("{\"from\":1,\"to\":2}")).hashMessage();
        Assert.assertEquals(32, hash.length);
    }

    @Test
    public void missingTo_isRejected() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(mailJson("{\"from\":1}"));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for missing field 'to'");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("'to'"));
        }
    }

    @Test
    public void missingFrom_isRejected() throws Exception {
        // The other half of the collision pair: {to:1} must not silently encode
        // to the same bytes {from:1} used to produce.
        StructuredDataEncoder encoder = new StructuredDataEncoder(mailJson("{\"to\":1}"));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for missing field 'from'");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("'from'"));
        }
    }

    @Test
    public void nestedStructMissingField_isRejected() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(nestedJson("{\"a\":1}"));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for missing nested field 'b'");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("'b'"));
        }
    }

    private static String structArrayJson(String elementsBody) {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"}],"
                + "\"Outer\":[{\"name\":\"items\",\"type\":\"Inner[]\"}],"
                + "\"Inner\":[{\"name\":\"a\",\"type\":\"uint256\"},"
                + "{\"name\":\"b\",\"type\":\"uint256\"}]"
                + "},"
                + "\"primaryType\":\"Outer\","
                + "\"domain\":{\"name\":\"Test\"},"
                + "\"message\":{\"items\":" + elementsBody + "}"
                + "}";
    }

    private static String fullDomainJson() {
        return "{"
                + "\"types\":{"
                + "\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},"
                + "{\"name\":\"version\",\"type\":\"string\"}],"
                + "\"Mail\":[{\"name\":\"from\",\"type\":\"uint256\"}]"
                + "},"
                + "\"primaryType\":\"Mail\","
                + "\"domain\":{\"name\":\"Test\",\"version\":\"1\"},"
                + "\"message\":{\"from\":1}"
                + "}";
    }

    @Test
    public void structArrayElementMissingField_isRejected() throws Exception {
        // Array elements of struct type recurse through encodeData per element;
        // the guard must fire there too, not just for top-level/nested fields.
        StructuredDataEncoder encoder =
                new StructuredDataEncoder(structArrayJson("[{\"a\":1}]"));
        try {
            encoder.hashMessage();
            Assert.fail("Expected IllegalArgumentException for missing array-element field 'b'");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("'b'"));
        }
    }

    @Test
    public void fullyPopulatedDomain_hashesSuccessfully() throws Exception {
        // Guards the legitimate-domain path: if the domain deserializer or
        // hashDomain ever stops mapping a standard field, this catches the
        // "everything throws" regression the reject-tests cannot see.
        byte[] hash = new StructuredDataEncoder(fullDomainJson()).hashDomain();
        Assert.assertEquals(32, hash.length);
    }

    @Test
    public void declaredDomainFieldAbsent_isRejected() throws Exception {
        StructuredDataEncoder encoder = new StructuredDataEncoder(partialDomainJson());
        try {
            encoder.hashDomain();
            Assert.fail("Expected IllegalArgumentException for missing domain field 'version'");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage(), expected.getMessage().contains("'version'"));
        }
    }
}
