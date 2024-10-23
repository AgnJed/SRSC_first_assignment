package service;

/**
 * Represents the result of an encryption operation.
 * Contains the encrypted text, authentication tag, and IV.
 */
public class EncryptionResult {
    private final String encryptedText;
    private final String authTag;
    private final String iv;

    public EncryptionResult(String encryptedText, String authTag, String iv) {
        this.encryptedText = encryptedText;
        this.authTag = authTag;
        this.iv = iv;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public String getAuthTag() {
        return authTag;
    }
    public String getIv() {
        return iv;
    }

}
