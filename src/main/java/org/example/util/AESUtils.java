package org.example.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

public class AESUtils {

    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Return the Base64-encode bytes of AES encryption.
     *
     * @param data The data.
     * @param key  The key.
     * @param iv   The buffer with the IV. The contents of the
     *             buffer are copied to protect against subsequent modification.
     * @return the Base64-encode bytes of AES encryption
     */
    public static byte[] encrypt2Base64(final byte[] data,
                                        final byte[] key,
                                        final byte[] iv) {
        return Base64.getEncoder().encode(encrypt(data, key, iv));
    }

    public static byte[] encrypt(final byte[] data, final byte[] key, final byte[] iv) {
        return symmetricTemplate(data, key, iv, true);
    }

    /**
     * Return the bytes of AES decryption for Base64-encode bytes.
     *
     * @param data The data.
     * @param key  The key.
     * @param iv   The buffer with the IV. The contents of the
     *             buffer are copied to protect against subsequent modification.
     * @return the bytes of AES decryption for Base64-encode bytes
     */
    public static byte[] decryptBase64(final byte[] data,
                                       final byte[] key,
                                       final byte[] iv) {
        return decrypt(Base64.getDecoder().decode(data), key, iv);
    }

    public static byte[] decrypt(final byte[] data, final byte[] key, final byte[] iv) {
        return symmetricTemplate(data, key, iv, false);
    }

    /**
     * Return the bytes of symmetric encryption or decryption.
     *
     * @param data      The data.
     * @param key       The key.
     * @param isEncrypt True to encrypt, false otherwise.
     * @return the bytes of symmetric encryption or decryption
     */
    private static byte[] symmetricTemplate(final byte[] data,
                                            final byte[] key,
                                            final byte[] iv,
                                            final boolean isEncrypt) {
        if (data == null || data.length == 0 || key == null || key.length == 0) return null;
        try {
            SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AESUtils.DEFAULT_CIPHER_ALGORITHM);
            if (iv == null || iv.length == 0) {
                cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
            } else {
                AlgorithmParameterSpec params = new IvParameterSpec(iv);
                cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, params);
            }
            return cipher.doFinal(data);
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }
}