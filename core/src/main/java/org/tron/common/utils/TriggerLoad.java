package org.tron.common.utils;


import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.FunctionReturnDecoder;
import org.tron.common.crypto.TypeReference;
import org.tron.common.crypto.datatypes.DynamicArray;
import org.tron.config.Parameter;
import org.tron.protos.contract.SmartContractOuterClass.SmartContract.ABI;
import org.tron.walletserver.AddressUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class TriggerLoad {


    public static final int DATAWORD_UNIT_SIZE = 32;

    private enum Type {
        UNKNOWN,
        INT_NUMBER,
        BOOL,
        FLOAT_NUMBER,
        FIXED_BYTES,
        ADDRESS,
        STRING,
        BYTES,
    }

    public static Map<String, String> parseTriggerData(byte[] data, ABI.Entry entry) {
        Map<String, String> map = new LinkedHashMap<>();
        if (ArrayUtils.isEmpty(data)) {
            return map;
        }

        // the first is the signature.
        List<ABI.Entry.Param> list = entry.getInputsList();
        int startIndex = 0;
        try {
            // this one starts from the first position.
            int index = 0;
            for (int i = 0; i < list.size(); ++i) {
                ABI.Entry.Param param = list.get(i);
                if (param.getIndexed()) {
                    continue;
                }
                if (startIndex == 0) {
                    startIndex = i;
                }

                String str = parseDataBytes(data, param.getType(), index++);
                if (!AddressUtil.isEmpty(param.getName())) {
//                    map.put(param.getName(), str);
                    // todo     4.4.1 Modify, replace all keys with integers
                    map.put("" + i, str);
                }


            }
            if (list.size() == 0) {
                map.put("0", Hex.toHexString(data));
            }
        } catch (UnsupportedOperationException e) {
            map.clear();
            map.put(String.valueOf(startIndex), Hex.toHexString(data));
        }
        return map;
    }


    public static Map<String, String> parseTriggerDataByFun(byte[] data, String fun) {
        Map<String, String> map = new LinkedHashMap<>();
        try {
            if (AddressUtil.isEmpty(fun) || !fun.contains("(") || !fun.contains(")")) return map;

            fun = fun.substring(fun.indexOf("(") + 1, fun.indexOf(")"));

            if (AddressUtil.isEmpty(fun) || fun.contains("(") || fun.contains(")")) return map;


            List<String> list = java.util.Arrays.asList(fun.split(","));
            int startIndex = 0;

            if (list != null
                    && list.size() == 1
                    && list.get(0).contains("[]")) {
                return parseDataByArray(data, fun);
            }
            if (ArrayUtils.isEmpty(data)) {
                return map;
            }
            try {
                // this one starts from the first position.
                int index = 0;
                for (int i = 0; i < list.size(); ++i) {

                    if (startIndex == 0) {
                        startIndex = i;
                    }

                    String str = parseDataBytes(data, list.get(i), index++);
                    map.put("" + i, str);

                }
                if (list.size() == 0) {
                    map.put("0", Hex.toHexString(data));
                }
            } catch (Exception e) {
                map.clear();
                map.put(String.valueOf(startIndex), Hex.toHexString(data));
            }
            return map;

        } catch (Exception e) {
            LogUtils.e(e);
            return map;

        }

    }

    private static Map<String, String> parseDataByArray(byte[] data, String typeStr) {
        Map<String, String> map = new LinkedHashMap<>();
        try {
            if (!Pattern.matches("^[A-Za-z][A-Za-z0-9]*\\[\\]$", typeStr)) {
                return map;
            }
            String elementType = typeStr.substring(0, typeStr.length() - 2);
            if (basicType(elementType) == Type.UNKNOWN) {
                return map;
            }

            // A single dynamic ABI argument points to its value immediately after the head word.
            int arrayOffset = intValueExact(subBytes(data, 0, DATAWORD_UNIT_SIZE));
            if (arrayOffset != DATAWORD_UNIT_SIZE) {
                return map;
            }

            List<org.tron.common.crypto.datatypes.Type> decoded =
                    decodeArrayWithWeb3j(data, typeStr);
            if (decoded.size() != 1 || !(decoded.get(0) instanceof DynamicArray)) {
                return map;
            }
            DynamicArray<?> array = (DynamicArray<?>) decoded.get(0);
            map.put("0", formatArrayValues(array.getValue(), basicType(elementType)));
            return map;
        } catch (Exception e) {
            LogUtils.e(e);
            return map;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<org.tron.common.crypto.datatypes.Type> decodeArrayWithWeb3j(
            byte[] data, String typeStr) {
        try {
            TypeReference<org.tron.common.crypto.datatypes.Type> typeReference =
                    (TypeReference<org.tron.common.crypto.datatypes.Type>)
                            TypeReference.makeTypeReference(typeStr);
            return FunctionReturnDecoder.decode(
                    Hex.toHexString(data), Collections.singletonList(typeReference));
        } catch (Exception e) {
            LogUtils.e(e);
            return Collections.emptyList();
        }
    }

    private static String formatArrayValues(
            List<?> values, Type elementKind) {
        List<String> displayValues = new ArrayList<>(values.size());
        for (Object value : values) {
            org.tron.common.crypto.datatypes.Type abiValue =
                    (org.tron.common.crypto.datatypes.Type) value;
            Object nativeValue = abiValue.getValue();
            if (elementKind == Type.ADDRESS) {
                byte[] address = Hex.decode(
                        org.tron.common.bip32.Numeric.cleanHexPrefix(String.valueOf(nativeValue)));
                byte[] last20Bytes = Arrays.copyOfRange(
                        address, address.length - 20, address.length);
                displayValues.add(AddressUtil.encode58Check(convertToTronAddress(last20Bytes)));
            } else if (nativeValue instanceof byte[]) {
                String hexValue = Hex.toHexString((byte[]) nativeValue);
                displayValues.add(elementKind == Type.BYTES ? "0x" + hexValue : hexValue);
            } else {
                displayValues.add(String.valueOf(nativeValue));
            }
        }
        if (elementKind != Type.STRING) {
            return displayValues.toString();
        }
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < displayValues.size(); i++) {
            if (i > 0) {
                result.append(", ");
            }
            result.append('"')
                    .append(displayValues.get(i)
                            .replace("\\", "\\\\")
                            .replace("\"", "\\\"")
                            .replace("\n", "\\n")
                            .replace("\r", "\\r"))
                    .append('"');
        }
        return result.append(']').toString();
    }

    private static String parseDataBytes(byte[] data, String typeStr, int index) {

        try {
            byte[] startBytes = subBytes(data, index * DATAWORD_UNIT_SIZE, DATAWORD_UNIT_SIZE);
            Type type = basicType(typeStr);
            // accepted: [Q-04] Negative intN is uncommon and bytesN padding is display-only; calldata, signing, broadcast, and execution are unchanged.
            if (type == Type.INT_NUMBER) {
                // maximum value：ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                // 115792089237316195423570985008687907853269984665640564039457584007913129639935
                //todo 4.4.1 Modify the output num to be a positive number (the original maximum output is -1）
                return new BigInteger(1, startBytes).toString();
            } else if (type == Type.BOOL) {
                return String.valueOf(!isZero(startBytes));
            } else if (type == Type.FIXED_BYTES) {
                return Hex.toHexString(startBytes);
            } else if (type == Type.ADDRESS) {
                byte[] last20Bytes = Arrays.copyOfRange(startBytes, 12, startBytes.length);
                return AddressUtil.encode58Check(convertToTronAddress(last20Bytes));
            } else if (type == Type.STRING || type == Type.BYTES) {
                int start = intValueExact(startBytes);
                byte[] lengthBytes = subBytes(data, start, DATAWORD_UNIT_SIZE);
                // this length is byte count. no need X 32
                int length = intValueExact(lengthBytes);
                int Max = 1024 * 1024 * 1;//1MB
                if (length == 0 || length > Max) {
                    return "";
                }
                byte[] realBytes = subBytes(data, start + DATAWORD_UNIT_SIZE, length);
                return type == Type.STRING ? new String(realBytes) : Hex.toHexString(realBytes);
            }
        } catch (OutputLengthException | ArithmeticException e) {
        }
        throw new UnsupportedOperationException("unsupported type:" + typeStr);
    }

    // don't support these type yet : bytes32[10][10]  OR  bytes32[][10]
    private static Type basicType(String type) {
        if (!Pattern.matches("^.*\\[\\d*\\]$", type)) {
            // ignore not valide type such as "int92", "bytes33", these types will be compiled failed.
            if ((type.startsWith("int") || type.startsWith("uint"))) {
                return Type.INT_NUMBER;
            } else if (type.equals("bool")) {
                return Type.BOOL;
            } else if (type.equals("address")) {
                return Type.ADDRESS;
            } else if (Pattern.matches("^bytes\\d+$", type)) {
                return Type.FIXED_BYTES;
            } else if (type.equals("string")) {
                return Type.STRING;
            } else if (type.equals("bytes")) {
                return Type.BYTES;
            }
        }
        return Type.UNKNOWN;
    }

    private static Integer intValueExact(byte[] data) {
        // ABI offsets/lengths are non-negative; treat the word as unsigned and reject
        // values that do not fit into an int instead of silently truncating. The thrown
        // ArithmeticException is handled by the caller's catch block.
        // BigInteger#intValueExact needs API 31; an unsigned value fits into an
        // int exactly when its bit length is at most 31.
        BigInteger value = new BigInteger(1, data);
        if (value.bitLength() > 31) {
            throw new ArithmeticException("BigInteger out of int range");
        }
        return value.intValue();
    }

    private static byte[] subBytes(byte[] src, int start, int length) {
        if (ArrayUtils.isEmpty(src) || start < 0 || start > src.length || length < 0) {
            throw new OutputLengthException("data start:" + start + ", length:" + length);
        }
        if (length > src.length - start) {
            throw new OutputLengthException("not enough bytes");
        }
        byte[] dst = new byte[length];
        System.arraycopy(src, start, dst, 0, length);
        return dst;
    }

    private static boolean isZero(byte[] data) {
        for (byte tmp : data) {
            if (tmp != 0) {
                return false;
            }
        }
        return true;
    }

    public static byte[] convertToTronAddress(byte[] address) {
        if (address.length == 20) {
            byte[] newAddress = new byte[21];
            byte[] temp = new byte[]{Parameter.CommonConstant.ADD_PRE_FIX_BYTE};
            System.arraycopy(temp, 0, newAddress, 0, temp.length);
            System.arraycopy(address, 0, newAddress, temp.length, address.length);
            address = newAddress;
        }
        return address;
    }
}
