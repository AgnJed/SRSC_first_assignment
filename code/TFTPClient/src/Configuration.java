package TFTPClient.src;

import java.util.HashMap;
import java.util.Map;

public class Configuration {
    private String confidentialityAlgorithm;
    private byte[] symmetricKey;
    private Integer symmetricKeySize;
    private Integer ivSize;
    private byte[] iv;
    private String integrity;
    private String hash;
    private String hmac;
    private byte[] hmacKey;
    private Integer hmacKeySize;

    /**
     * Parse the configuration from a map.
     * TODO improve code maybe without reflection
     *
     * @param configuration The configuration as a map.
     * @return The configuration object.
     */
    public static Configuration parceConfiguration(Map<String, String> configuration) {
        Configuration config = new Configuration();
        config.setConfidentialityAlgorithm(configuration.get(ConfigurationKeys.CONFIDENTIALITY.name()));
        config.setSymmetricKey(configuration.get(ConfigurationKeys.SYMMETRIC_KEY.name()));
        config.setSymmetricKeySize(configuration.get(ConfigurationKeys.SYMMETRIC_KEY_SIZE.name()));
        config.setIvSize(configuration.get(ConfigurationKeys.IV_SIZE.name()));
        config.setIv(configuration.get(ConfigurationKeys.IV.name()));
        config.setIntegrity(configuration.get(ConfigurationKeys.INTEGRITY.name()));
        config.setHash(configuration.get(ConfigurationKeys.H.name()));
        config.setHmac(configuration.get(ConfigurationKeys.HMAC.name()));
        config.setHmacKey(configuration.get(ConfigurationKeys.HMAC_KEY.name()));
        config.setHmacKeySize(configuration.get(ConfigurationKeys.HMAC_KEY_SIZE.name()));
        return config;
    }

    public String getConfidentialityAlgorithm() {
        return confidentialityAlgorithm;
    }

    public void setConfidentialityAlgorithm(String confidentialityAlgorithm) {
        this.confidentialityAlgorithm = confidentialityAlgorithm;
    }

    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(String symmetricKey) {
        this.symmetricKey = toByteArray(symmetricKey);
        this.symmetricKeySize = symmetricKey.length();
    }

    public Integer getSymmetricKeySize() {
        return symmetricKeySize;
    }

    public void setSymmetricKeySize(String symmetricKeySize) {
        this.symmetricKeySize = parseOrNull(symmetricKeySize);
    }

    public Integer getIvSize() {
        return ivSize == null ? 0 : ivSize;
    }

    public void setIvSize(String ivSize) {
        this.ivSize = parseOrNull(ivSize);
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
        this.ivSize = this.iv.length;
    }

    public void setIv(String iv) {
        this.iv = toByteArray(iv);
        this.ivSize = iv.length();
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getHmac() {
        return hmac;
    }

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }

    public byte[] getHmacKey() {
        return hmacKey;
    }

    public void setHmacKey(String hmacKey) {
        this.hmacKey = toByteArray(hmacKey);
        this.hmacKeySize = hmacKey.length();
    }

    public Integer getHmacKeySize() {
        return hmacKeySize;
    }

    public void setHmacKeySize(String hmacKeySize) {
        this.hmacKeySize = parseOrNull(hmacKeySize);
    }

    /**
     * Convert the configuration to a map.
     * TODO improve code maybe without reflection
     *
     * @return The configuration as a map.
     */
    public Map<String, String> toMap() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put(ConfigurationKeys.CONFIDENTIALITY.name(), confidentialityAlgorithm);
        configMap.put(ConfigurationKeys.SYMMETRIC_KEY.name(), symmetricKey == null ? null : toString(symmetricKey));
        configMap.put(ConfigurationKeys.SYMMETRIC_KEY_SIZE.name(), symmetricKeySize == null ? null : symmetricKeySize.toString());
        configMap.put(ConfigurationKeys.IV_SIZE.name(), ivSize == null ? null : ivSize.toString());
        configMap.put(ConfigurationKeys.IV.name(), toString(iv));
        configMap.put(ConfigurationKeys.INTEGRITY.name(), integrity);
        configMap.put(ConfigurationKeys.H.name(), hash);
        configMap.put(ConfigurationKeys.HMAC.name(), hmac);
        configMap.put(ConfigurationKeys.HMAC_KEY.name(), hmacKey == null ? null : toString(hmacKey));
        configMap.put(ConfigurationKeys.HMAC_KEY_SIZE.name(), hmacKeySize == null ? null : hmacKeySize.toString());
        return configMap;
    }

    /**
     * Get the integrity mode from the stored value.
     *
     * @return The integrity mode.
     */
    public IntegrityMode getIntegrityMode() {
        return IntegrityMode.valueOf(integrity);
    }

    /**
     * Parse a string to an integer or return null if it is not possible.
     *
     * @param input The string to parse.
     * @return The integer or null.
     */
    public Integer parseOrNull(String input) {
        try {
            return input != null ? Integer.parseInt(input) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean isGCMMode() {
        return confidentialityAlgorithm.contains("GCM");
    }

    public static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }


    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    /**
     * Enum to represent the keys in the configuration file.
     */
    enum ConfigurationKeys {
        CONFIDENTIALITY,
        SYMMETRIC_KEY,
        SYMMETRIC_KEY_SIZE,
        IV_SIZE,
        IV,
        INTEGRITY,
        H,
        HMAC,
        HMAC_KEY,
        HMAC_KEY_SIZE
    }

    /**
     * Enum that represents the integrity mode
     */
    public enum IntegrityMode {
        H, HMAC
    }
}
