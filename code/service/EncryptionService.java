package service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-GCM encryption service
 */
public class EncryptionService {

    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    private static final int IV_SIZE_BYTES = 16;

    /**
     * Encrypts the given plaintext using AES-GCM with the given key and IV.
     * @param plaintext The plaintext to encrypt
     * @param aad Additional authenticated data
     * @param key The key to use
     * @param iv The initialization vector to use
     * @param authTagLength The length of the authentication tag in bits (128, 120, 112, 104, 96)
     * @return a {@link EncryptionResult} containing the encrypted text, authentication tag and IV
     * @throws Exception If an error occurs.
     */
    public static EncryptionResult encrypt(String plaintext, String aad, SecretKey key, byte[] iv, int authTagLength) throws Exception {

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec spec = new GCMParameterSpec(authTagLength, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.updateAAD(aad.getBytes());

        byte[] cipherText = cipher.doFinal(plaintext.getBytes());

        // Authentication tag is in the last N bytes of the result (N = authTagLength / 8)
        int authTagSize = authTagLength / 8; // in bytes
        byte[] authTag = new byte[authTagSize];
        System.arraycopy(cipherText, cipherText.length - authTagSize, authTag, 0, authTagSize);

        // The encrypted text is the rest of the result
        byte[] encryptedText = new byte[cipherText.length - authTagSize];
        System.arraycopy(cipherText, 0, encryptedText, 0, cipherText.length - authTagSize);

        String encryptedTextBase64 = Base64.getEncoder().encodeToString(encryptedText);
        String authTagBase64 = Base64.getEncoder().encodeToString(authTag);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);

        return new EncryptionResult(encryptedTextBase64, authTagBase64, ivBase64);
    }

    /**
     * Decrypts the given ciphertext using AES-GCM with the given key and IV.
     * @param cipherText The ciphertext to decrypt
     * @param aad Additional authenticated data
     * @param key The key to use
     * @param iv The initialization vector to use
     * @param authTagLength The length of the authentication tag in bits (128, 120, 112, 104, 96)
     * @return The decrypted plaintext
     * @throws Exception If an error occurs.
     */
    public static String decrypt(String cipherText, String aad, SecretKey key, byte[] iv, int authTagLength) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec spec = new GCMParameterSpec(authTagLength, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        cipher.updateAAD(aad.getBytes());

        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(plainText);
    }

    /**
     * Generates a random AES key.
     * @return The generated key
     * @throws Exception If an error occurs.
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    /**
     * Generates a random initialization vector.
     * @return The generated IV
     */
    public static byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}