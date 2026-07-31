package org.tron.common.bip32;

import org.bouncycastle.math.ec.ECPoint;
import org.tron.common.crypto.Hash;

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
        byte[] i = Hash.hmacSha512("Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);
        Arrays.fill(i, (byte) 0);
        // BIP-32: the master private key I_L must be in [1, n-1]; otherwise the seed is invalid.
        BigInteger ilInt = new BigInteger(1, il);
        if (ilInt.signum() == 0 || ilInt.compareTo(Sign.CURVE.getN()) >= 0) {
            Arrays.fill(il, (byte) 0);
            Arrays.fill(ir, (byte) 0);
            throw new IllegalArgumentException("Invalid BIP-32 seed: master key not in [1, n-1]");
        }
        Bip32ECKeyPair keypair = Bip32ECKeyPair.create(il, ir);
        Arrays.fill(il, (byte) 0);
        Arrays.fill(ir, (byte) 0);

        return keypair;
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
        if (!hasPrivateKey()) {
            byte[] parentPublicKey = getPublicKeyPoint().getEncoded(true);
            ByteBuffer data = ByteBuffer.allocate(37);
            data.put(parentPublicKey);
            data.putInt(childNumber);
            byte[] i = Hash.hmacSha512(getChainCode(), data.array());
            byte[] il = Arrays.copyOfRange(i, 0, 32);
            byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
            Arrays.fill(i, (byte) 0);
            BigInteger ilInt = new BigInteger(1, il);
            Arrays.fill(il, (byte) 0);
            // BIP-32: if parse(I_L) >= n the child is invalid and must be skipped.
            if (ilInt.compareTo(Sign.CURVE.getN()) >= 0) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: I_L >= n");
            }
            ECPoint ki = Sign.publicPointFromPrivate(ilInt).add(getPublicKeyPoint());
            // BIP-32: the resulting public point must not be the point at infinity.
            if (ki.isInfinity()) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: point at infinity");
            }

            return new Bip32ECKeyPair(null,
                    Sign.publicFromPoint(ki.getEncoded(true)),
                    childNumber, chainCode, this);
        } else {
            ByteBuffer data = ByteBuffer.allocate(37);
            if (isHardened(childNumber)) {
                data.put(getPrivateKeyBytes33());
            } else {
                byte[] parentPublicKey = getPublicKeyPoint().getEncoded(true);
                data.put(parentPublicKey);
            }
            data.putInt(childNumber);
            byte[] i = Hash.hmacSha512(getChainCode(), data.array());
            byte[] il = Arrays.copyOfRange(i, 0, 32);
            byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
            Arrays.fill(i, (byte) 0);
            BigInteger ilInt = new BigInteger(1, il);
            Arrays.fill(il, (byte) 0);
            // BIP-32: if parse(I_L) >= n the child is invalid and must be skipped.
            if (ilInt.compareTo(Sign.CURVE.getN()) >= 0) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: I_L >= n");
            }
            BigInteger privateKey = getPrivateKey().add(ilInt).mod(Sign.CURVE.getN());
            // BIP-32: a derived private key of 0 is invalid and must be skipped.
            if (privateKey.signum() == 0) {
                throw new IllegalArgumentException("Invalid BIP-32 child key: derived private key is 0");
            }

            return new Bip32ECKeyPair(privateKey, Sign.publicKeyFromPrivate(privateKey),
                    childNumber, chainCode, this);
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

    public byte[] getChainCode() {
        return chainCode;
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
        System.arraycopy(priv, 0, bytes33, numBytes - priv.length, priv.length);
        return bytes33;
    }

    private boolean hasPrivateKey() {
        return this.getPrivateKey() != null || parentHasPrivate;
    }

    private static byte[] bigIntegerToBytes32(BigInteger b) {
        final int numBytes = 32;

        byte[] src = b.toByteArray();
        byte[] dest = new byte[numBytes];
        boolean isFirstByteOnlyForSign = src[0] == 0;
        int length = isFirstByteOnlyForSign ? src.length - 1 : src.length;
        int srcPos = isFirstByteOnlyForSign ? 1 : 0;
        int destPos = numBytes - length;
        System.arraycopy(src, srcPos, dest, destPos, length);
        return dest;
    }

    private static boolean isHardened(int a) {
        return (a & HARDENED_BIT) != 0;
    }
}
