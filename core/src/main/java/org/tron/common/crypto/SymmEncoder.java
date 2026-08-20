package org.tron.common.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.tron.common.utils.LogUtils;
import org.tron.net.CipherException;

public class SymmEncoder {

  public static SecretKey restoreSecretKey(byte[] secretBytes, String algorithm) {
    SecretKey secretKey = new SecretKeySpec(secretBytes, algorithm);
    return secretKey;
  }

  public static byte[] AES128EcbEnc(byte[] plain, byte[] aesKey) throws CipherException {
    if (aesKey == null || aesKey.length != 16) {
      return null;
    }
    if (plain == null || (plain.length & 0x0F) != 0) {
      return null;
    }

    SecretKey key = restoreSecretKey(aesKey, "AES");
    return AesEcbEncode(plain, key);
  }

  // Legacy decryption only. Callers must atomically persist the replacement keystore and
  // remove the legacy ciphertext only after the new keystore write succeeds.
  public static byte[] AES128EcbDec(byte[] encoded, byte[] aesKey) throws CipherException {
    if (aesKey == null || aesKey.length != 16) {
      return null;
    }
    if (encoded == null || (encoded.length & 0x0F) != 0) {
      return null;
    }

    SecretKey key = restoreSecretKey(aesKey, "AES");
    return AesEcbDecode(encoded, key);
  }


  private static byte[] AesEcbEncode(byte[] plainText, SecretKey key) throws CipherException {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher.doFinal(plainText);
    } catch (GeneralSecurityException ex) {
      LogUtils.e("AES/ECB encrypt failed: " + ex.getMessage(), ex);
      throw new CipherException("AES/ECB encrypt failed", ex);
    }
  }

  private static byte[] AesEcbDecode(byte[] encodedText, SecretKey key) throws CipherException {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key);
      return cipher.doFinal(encodedText);
    } catch (GeneralSecurityException ex) {
      LogUtils.e("AES/ECB decrypt failed: " + ex.getMessage(), ex);
      throw new CipherException("AES/ECB decrypt failed", ex);
    }
  }


  // Legacy decryption only. Callers must atomically persist the replacement keystore and
  // remove the legacy ciphertext only after the new keystore write succeeds.
  public static byte[] AESEcbDec(byte[] encoded, byte[] aesKey) throws CipherException {
    if (aesKey == null || aesKey.length != 16) {
      return null;
    }
    if (encoded == null) {
      return null;
    }

    SecretKey key = restoreSecretKey(aesKey, "AES");
    return AesEcbPKCS7Decode(encoded, key);
  }

  private static byte[] AesEcbPKCS7Decode(byte[] encodedText, SecretKey key) throws CipherException {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
      cipher.init(Cipher.DECRYPT_MODE, key);
      return cipher.doFinal(encodedText);
    } catch (GeneralSecurityException ex) {
      LogUtils.e("AES/ECB/PKCS7 decrypt failed: " + ex.getMessage(), ex);
      throw new CipherException("AES/ECB/PKCS7 decrypt failed", ex);
    }
  }
}
