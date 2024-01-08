package avi.dew.lib.controller;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesExample {

    private static final String aesKeyHex = "2b7e151628aed2a6abf7158809cf4f3c";

    public static void main(String[] args) {
        // Data received from the client after encryption
        String encryptedData = "U2FsdGVkX18BuhyMj7z4Ou/eNjZkD7IoRz2l0j07vFA=";

        // Decrypt the data
        try {
            String decryptedData = decryptData(encryptedData, aesKeyHex);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String decryptData(String encryptedData, String keyHex) throws Exception {
        try {
            // Convert the hexadecimal key to a byte array
            byte[] keyBytes = hexStringToByteArray(keyHex);

            // Decode the Base64-encoded encrypted data
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            // Extract the IV from the first 16 bytes
            byte[] iv = new byte[16];
            System.arraycopy(encryptedBytes, 0, iv, 0, iv.length);

            // Initialize the cipher with the key, IV, and decryption mode
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            // Decrypt the data, excluding the IV
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes, iv.length, encryptedBytes.length - iv.length);

            // Convert the decrypted data to a String
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new Exception("Error decrypting data", e);
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) +
                    Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
