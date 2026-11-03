package org.tron.common.bip32;

import org.bouncycastle.math.ec.ECPoint;
import org.tron.common.crypto.Hash;
import org.tron.common.utils.SensitiveData;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BIP-32 key pair.
 * <p>
 * <p>Adapted from:
 * https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/crypto/DeterministicKey.java
 */
public class Bip32ECKeyPair extends ECKeyPair {
    public static final int HARDENED_BIT = 0x80000000;

    private final boolean parentHasPrivate;
    private final int childNumber;
    private final int depth;
    private final byte[] chainCode;
    private int parentFingerprint;

    private ECPoint publicKeyPoint;

    public Bip32ECKeyPair(BigInteger privateKey, BigInteger publicKey, int childNumber,
                          byte[] chainCode, Bip32ECKeyPair parent) {
        super(privateKey, publicKey);
        this.parentHasPrivate = parent != null && parent.hasPrivateKey();
        this.childNumber = childNumber;
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.parentFingerprint = parent != null ? parent.getFingerprint() : 0;
    }

    public static Bip32ECKeyPair create(BigInteger privateKey, byte[] chainCode) {
        return new Bip32ECKeyPair(privateKey, Sign.publicKeyFromPrivate(privateKey),
                0, chainCode, null);
    }

    public static Bip32ECKeyPair create(byte[] privateKey, byte[] chainCode) {
        return create(Numeric.toBigInt(privateKey), chainCode);
    }

    public static Bip32ECKeyPair generateKeyPair(byte[] seed) {
        byte[] i = null;
        byte[] il = null;
        byte[] ir = null;
        try {
            i = Hash.hmacSha512("Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);
            il = Arrays.copyOfRange(i, 0, 32);
            ir = Arrays.copyOfRange(i, 32, 64);
            BigInteger scalar = new BigInteger(1, il);
            if (scalar.signum() == 0 || scalar.compareTo(Sign.CURVE.getN()) >= 0) {
                throw new IllegalArgumentException("Invalid BIP-32 seed: master key not in [1, n-1]");
            }
            return Bip32ECKeyPair.create(il, ir);
        } finally {
            SensitiveData.clear(i);
            SensitiveData.clear(il);
            SensitiveData.clear(ir);
        }
    }

    public static Bip32ECKeyPair deriveKeyPair(Bip32ECKeyPair master, int[] path) {
        Bip32ECKeyPair curr = master;
        if (path != null) {
            for (int childNumber : path) {
                curr = curr.deriveChildKey(childNumber);
            }
        }

        return curr;
    }

    private Bip32ECKeyPair deriveChildKey(int childNumber) {
        byte[] data = new byte[37];
        byte[] parentPrivate = null;
        byte[] parentChain = null;
        byte[] i = null;
        byte[] il = null;
        byte[] childChain = null;
        try {
            boolean privateDerivation = hasPrivateKey();
            ByteBuffer buffer = ByteBuffer.wrap(data);
            if (privateDerivation && isHardened(childNumber)) {
                parentPrivate = getPrivateKeyBytes33();
                buffer.put(parentPrivate);
            } else {
                buffer.put(getPublicKeyPoint().getEncoded(true));
            }
            buffer.putInt(childNumber);
            parentChain = getChainCode();
            i = Hash.hmacSha512(parentChain, data);
            il = Arrays.copyOfRange(i, 0, 32);
            childChain = Arrays.copyOfRange(i, 32, 64);
            BigInteger scalar = new BigInteger(1, il);
            if (scalar.compareTo(Sign.CURVE.getN()) >= 0) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: I_L >= n");
            }
            if (!privateDerivation) {
                ECPoint point = Sign.publicPointFromPrivate(scalar).add(getPublicKeyPoint());
                if (point.isInfinity()) {
                    throw new IllegalArgumentException("Invalid BIP-32 child key: point at infinity");
                }
                return new Bip32ECKeyPair(null, Sign.publicFromPoint(point.getEncoded(true)),
                        childNumber, childChain, this);
            }
            BigInteger privateKey = getPrivateKey().add(scalar).mod(Sign.CURVE.getN());
            if (privateKey.signum() == 0) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: derived private key is 0");
            }
            // The constructor copies its chain code before this method clears its temporary.
            return new Bip32ECKeyPair(privateKey, Sign.publicKeyFromPrivate(privateKey),
                    childNumber, childChain, this);
        } finally {
            SensitiveData.clear(data);
            SensitiveData.clear(parentPrivate);
            SensitiveData.clear(parentChain);
            SensitiveData.clear(i);
            SensitiveData.clear(il);
            SensitiveData.clear(childChain);
        }
    }

    private int getFingerprint() {
        byte[] id = getIdentifier();
        return id[3] & 0xFF | (id[2] & 0xFF) << 8 | (id[1] & 0xFF) << 16 | (id[0] & 0xFF) << 24;
    }

    public int getDepth() {
        return depth;
    }

    public int getParentFingerprint() {
        return parentFingerprint;
    }

    /** Returns a copy so callers cannot alter the chain code used for child derivation. */
    public byte[] getChainCode() {
        return Arrays.copyOf(chainCode, chainCode.length);
    }

    public int getChildNumber() {
        return childNumber;
    }

    private byte[] getIdentifier() {
        return Hash.sha256hash160(getPublicKeyPoint().getEncoded(true));
    }

    // accepted (Q-07): this always derives the public point from the private key and ignores
    // any stored public key. A public-key-only (watch-only / xpub) Bip32ECKeyPair has a null
    // private key, so getPublicKeyPoint() — and hence the non-private deriveChildKey branch —
    // would NPE, and hardened derivation from such a key is not rejected. Left as-is: every
    // Bip32ECKeyPair in this codebase is built from a private key (see the create()/
    // generateKeyPair() factories) and there is no watch-only derivation path, so the null
    // case is unreachable in practice. Documented as a known limitation rather than adding a
    // public-key point-decode path to a shipping wallet.
    public ECPoint getPublicKeyPoint() {
        if (publicKeyPoint == null) {
            publicKeyPoint = Sign.publicPointFromPrivate(getPrivateKey());
        }
        return publicKeyPoint;
    }

    public byte[] getPrivateKeyBytes33() {
        final int numBytes = 33;

        byte[] bytes33 = new byte[numBytes];
        byte[] priv = bigIntegerToBytes32(getPrivateKey());
        try {
            System.arraycopy(priv, 0, bytes33, numBytes - priv.length, priv.length);
            return bytes33;
        } finally {
            SensitiveData.clear(priv);
        }
    }

    private boolean hasPrivateKey() {
        return this.getPrivateKey() != null || parentHasPrivate;
    }

    private static byte[] bigIntegerToBytes32(BigInteger b) {
        final int numBytes = 32;

        byte[] src = b.toByteArray();
        try {
            byte[] dest = new byte[numBytes];
            boolean signByte = src[0] == 0;
            int length = signByte ? src.length - 1 : src.length;
            System.arraycopy(src, signByte ? 1 : 0, dest, numBytes - length, length);
            return dest;
        } finally {
            SensitiveData.clear(src);
        }
    }

    private static boolean isHardened(int a) {
        return (a & HARDENED_BIT) != 0;
    }
}
