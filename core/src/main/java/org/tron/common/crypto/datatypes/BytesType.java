/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.tron.common.crypto.datatypes;

import java.util.Arrays;

/** Binary sequence of bytes. */
public abstract class BytesType implements Type<byte[]> {

    private byte[] value;
    private String type;

    public BytesType(byte[] src, String type) {
        // Defensive copy: don't retain the caller's array. Without this, the caller
        // (or a consumer of getValue()) could mutate the backing array in place and
        // break the value's immutability, including poisoning shared DEFAULT
        // constants such as Bytes32.DEFAULT / DynamicBytes.DEFAULT.
        this.value = src == null ? null : src.clone();
        this.type = type;
    }

    @Override
    public int bytes32PaddedLength() {
        if (value == null) {
            return MAX_BYTE_LENGTH;
        }
        return value.length <= 32
                ? MAX_BYTE_LENGTH
                : (value.length / MAX_BYTE_LENGTH + 1) * MAX_BYTE_LENGTH;
    }

    @Override
    public byte[] getValue() {
        // Return a copy so callers cannot mutate the internal (or shared DEFAULT) array.
        return value == null ? null : value.clone();
    }

    @Override
    public String getTypeAsString() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        BytesType bytesType = (BytesType) o;

        if (!Arrays.equals(value, bytesType.value)) {
            return false;
        }
        return type.equals(bytesType.type);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(value);
        result = 31 * result + type.hashCode();
        return result;
    }
}
