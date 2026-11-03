package org.tron.common.utils;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Best-effort clearing and UTF-8 conversion for application-owned secret buffers.
 * Inputs are borrowed and never modified; returned arrays belong to the caller.
 * This cannot erase immutable strings, runtime copies, or cryptographic provider state.
 */
public final class SensitiveData {
    private SensitiveData() {
    }

    public static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    public static void clear(char[] value) {
        if (value != null) {
            Arrays.fill(value, '\0');
        }
    }

    /** Matches String.getBytes(UTF_8), including replacement of malformed UTF-16. */
    public static byte[] toUtf8Bytes(char[] value) {
        if (value == null) {
            return null;
        }
        // UTF-8 needs at most three bytes per UTF-16 code unit. Allocate explicitly
        // so the temporary backing array remains accessible for clearing.
        byte[] temporary = new byte[Math.multiplyExact(value.length, 3)];
        try {
            ByteBuffer output = ByteBuffer.wrap(temporary);
            java.nio.charset.CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE);
            checkResult(encoder.encode(CharBuffer.wrap(value), output, true));
            checkResult(encoder.flush(output));
            return Arrays.copyOf(temporary, output.position());
        } catch (CharacterCodingException ex) {
            // Replacement is enabled and the output capacity covers every input.
            throw new IllegalStateException("UTF-8 encoding failed", ex);
        } finally {
            clear(temporary);
        }
    }

    /** Matches new String(bytes, UTF_8), including replacement of malformed UTF-8. */
    public static char[] fromUtf8Bytes(byte[] value) {
        if (value == null) {
            return null;
        }
        char[] temporary = new char[value.length];
        try {
            CharBuffer output = CharBuffer.wrap(temporary);
            java.nio.charset.CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE);
            checkResult(decoder.decode(ByteBuffer.wrap(value), output, true));
            checkResult(decoder.flush(output));
            return Arrays.copyOf(temporary, output.position());
        } catch (CharacterCodingException ex) {
            throw new IllegalStateException("UTF-8 decoding failed", ex);
        } finally {
            clear(temporary);
        }
    }

    private static void checkResult(CoderResult result) throws CharacterCodingException {
        if (!result.isUnderflow()) {
            result.throwException();
        }
    }
}
