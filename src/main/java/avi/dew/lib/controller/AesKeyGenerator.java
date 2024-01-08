package avi.dew.lib.controller;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AesKeyGenerator {

    public static void main(String[] args) {
        try {
            SecretKey aesKey = generateAESKey(256);
            byte[] keyBytes = aesKey.getEncoded();

            // Print the key in Base64 encoding
            String base64Key = Base64.getEncoder().encodeToString(keyBytes);
            System.out.println("AES Key (Base64): " + base64Key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }
}

