package org.example;

public class Main {
    public static void main(String[] args) throws Throwable {
        System.out.println("Hello world!");

        String text = "Hello world!";
        System.out.println("original text: " + text);

        String encryptedText = DynamicEncryptionUtils.encrypt(text);
        System.out.println("encrypted text: " + encryptedText);

        String hex2String = new String(DynamicEncryptionUtils.hexString2Bytes(encryptedText));
        System.out.println("hex2string text: " + hex2String);

        String decryptedText = DynamicEncryptionUtils.decrypt(encryptedText);
        System.out.println("decrypted text: " + decryptedText);
    }
}