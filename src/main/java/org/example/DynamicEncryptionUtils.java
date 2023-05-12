package org.example;

import org.example.util.AESUtils;
import org.example.util.HexUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class DynamicEncryptionUtils {

    private static final String KEY_ALGORITHM = "AES";

    public static SecretKey getSecretKey() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(secureRandom);
        return keyGenerator.generateKey();
    }

    /**
     * Function to initialize a vector with an arbitrary value
     */
    public static byte[] createInitializationVector() {
        // Used with encryption
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static String encrypt(String plainText) {
        try {
            SecretKey secretKey = getSecretKey();
            String secretKeyHexString = bytes2HexString(secretKey.getEncoded());

            byte[] initializationVector = createInitializationVector();
            String initializationVectorHexString = bytes2HexString(initializationVector);

            byte[] encryptedText = processEncryption(plainText, secretKey.getEncoded(), initializationVector);
            String encryptedTextHexString = bytes2HexString(encryptedText);

            return secretKeyHexString + initializationVectorHexString + encryptedTextHexString;
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] processEncryption(String plainText, byte[] key, byte[] iv) {
        try {
            return AESUtils.encrypt(plainText.getBytes(), key, iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt2Text(String encryptedText) {
        try {
            byte[] decryptedTextBytes = decrypt(encryptedText);
            if (decryptedTextBytes == null) {
                return null;
            }
            return new String(decryptedTextBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] decrypt(String encryptedText) {
        try {
            return processDecryption(encryptedText.getBytes());
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static byte[] processDecryption(byte[] encryptedData) {
        try {
            InputStream is = new ByteArrayInputStream(encryptedData);

            // Read 16-bit key, hex is 16*2
            byte[] secretKeyByes = new byte[16 * 2];
            is.read(secretKeyByes);
            // Convert hex string to bytes
            secretKeyByes = hexString2Bytes(new String(secretKeyByes));

            // Read 16-bit vector, hex is 16*2
            byte[] initializationVectorByes = new byte[16 * 2];
            is.read(initializationVectorByes);
            // Convert hex string to bytes
            initializationVectorByes = hexString2Bytes(new String(initializationVectorByes));

            // Read encrypted text
            byte[] encryptedTextBytes = new byte[is.available()];
            is.read(encryptedTextBytes);
            is.close();
            // Convert hex string to bytes
            encryptedTextBytes = hexString2Bytes(new String(encryptedTextBytes));

            SecretKey secretKey = new SecretKeySpec(secretKeyByes, 0, secretKeyByes.length, KEY_ALGORITHM);

            return AESUtils.decrypt(encryptedTextBytes, secretKey.getEncoded(), initializationVectorByes);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String bytes2HexString(byte[] bytes) {
        return HexUtils.bytes2HexString(bytes);
    }

    public static byte[] hexString2Bytes(String hexStr) {
        return HexUtils.hexString2Bytes(hexStr);
    }
}