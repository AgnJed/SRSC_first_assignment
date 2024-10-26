package java.IO;

import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.service.IntegrityMode;
import java.util.HashMap;
import java.util.Map;

public class FileAccess {

    // Default values for each field
    public static final String DEFAULT_CONFIDENTIALITY = "AES/CBC/PKCS5Padding";
    public static final String DEFAULT_SYMMETRIC_KEY = "00112233445566778899AABBCCDDEEFF";
    public static final int DEFAULT_SYMMETRIC_KEY_SIZE = 128;
    public static final int DEFAULT_IV_SIZE = 16;
    public static final String DEFAULT_IV = "0000000000000000";
    public static final String DEFAULT_INTEGRITY = "HMAC";
    public static final String DEFAULT_H = "SHA-256";
    public static final String DEFAULT_MAC = "HMAC-SHA256";
    public static final String DEFAULT_MAC_KEY = "A1B2C3D4E5F60708";
    public static final int DEFAULT_MAC_KEY_SIZE = 128;
    private static final Logger logger = LoggerFactory.getLogger(FileAccess.class);
    private static final String CONFIG_FILE_NAME = "testConfig.txt";
    private static final String CONFIDENTIALITY_KEY = "CONFIDENTIALITY";
    private static final String SYMMETRIC_KEY_KEY = "SYMMETRIC_KEY";
    private static final String SYMMETRIC_KEY_SIZE_KEY = "SYMMETRIC_KEY_SIZE";
    private static final String IV_SIZE_KEY = "IV Size";
    private static final String IV_KEY = "IV";
    private static final String INTEGRITY_KEY = "INTEGRITY";
    private static final String H_KEY = "H";
    private static final String MAC_KEY = "MAC";
    private static final String MACKEY_KEY = "MACKEY";
    private static final String MACKEY_SIZE_KEY = "MACKEY_SIZE";
    private static final String NULL_VALUE = "NULL";
    private String confidentialityAlgorithm;
    private byte[] symmetricKey;
    private Integer symmetricKeySize;
    private Integer ivSize;
    private String iv;
    private String integrity;
    private String h;
    private String mac;
    private byte[] macKey;
    private Integer macKeySize;

    public String getConfidentialityAlgorithm() {
        return confidentialityAlgorithm;
    }

    public void setConfidentialityAlgorithm(String confidentialityAlgorithm) {
        this.confidentialityAlgorithm = confidentialityAlgorithm;
    }

    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(byte[] symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public Integer getSymmetricKeySize() {
        return symmetricKeySize;
    }

    public void setSymmetricKeySize(Integer symmetricKeySize) {
        this.symmetricKeySize = symmetricKeySize;
    }

    public Integer getIvSize() {
        return ivSize;
    }

    public void setIvSize(Integer ivSize) {
        this.ivSize = ivSize;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getIntegrity() {
        return integrity;
    }

    public void setIntegrity(String integrity) {
        this.integrity = integrity;
    }

    public String getH() {
        return h;
    }

    public void setH(String h) {
        this.h = h;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    public Integer getMacKeySize() {
        return macKeySize;
    }

    public void setMacKeySize(Integer macKeySize) {
        this.macKeySize = macKeySize;
    }


    // Method to read the configuration file and populate fields
    public void readConfigFile(String filePath) {
        Map<String, String> configMap = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.contains(":")) continue;

                String[] parts = line.split(":", 2);
                String key = parts[0].trim();
                String value = parts[1].trim();

                configMap.put(key, NULL_VALUE.equalsIgnoreCase(value) ? null : value);
            }

            // Set fields, checking for "NULL" and using defaults if necessary
            setConfidentialityAlgorithm(getDefaultValue(configMap.get(CONFIDENTIALITY_KEY), DEFAULT_CONFIDENTIALITY));
            setSymmetricKey(getDefaultValue(configMap.get(SYMMETRIC_KEY_KEY), DEFAULT_SYMMETRIC_KEY).getBytes());
            setSymmetricKeySize(parseIntDefault(configMap.get(SYMMETRIC_KEY_SIZE_KEY), DEFAULT_SYMMETRIC_KEY_SIZE));
            setIvSize(parseIntDefault(configMap.get(IV_SIZE_KEY), DEFAULT_IV_SIZE));
            setIv(getDefaultValue(configMap.get(IV_KEY), DEFAULT_IV));
            setIntegrity(getDefaultValue(configMap.get(INTEGRITY_KEY), DEFAULT_INTEGRITY));
            setH(getDefaultValue(configMap.get(H_KEY), DEFAULT_H));
            setMac(getDefaultValue(configMap.get(MAC_KEY), DEFAULT_MAC));
            setMacKey(getDefaultValue(configMap.get(MACKEY_KEY), DEFAULT_MAC_KEY).getBytes());
            setMacKeySize(parseIntDefault(configMap.get(MACKEY_SIZE_KEY), DEFAULT_MAC_KEY_SIZE));

        } catch (IOException e) {
            logger.error(() -> "Error reading the config file: " + e.getMessage());
        }
    }


    // Method to write the generated IV to the configuration file
    public void writeConfigFile(String filePath) {
        String ivValue = generateIv(); // Generate a new IV

        // Read the existing configuration and replace the IV line
        StringBuilder updatedConfig = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Replace the line containing "IV:"
                if (line.startsWith("IV:")) {
                    updatedConfig.append("IV: ").append(ivValue).append("\n");
                } else {
                    updatedConfig.append(line).append("\n"); // Keep other lines unchanged
                }
            }
        } catch (IOException e) {
            logger.error(() -> "Error reading the config file: " + e.getMessage());
            return;
        }

        // Write the updated configuration back to the file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(updatedConfig.toString());
        } catch (IOException e) {
            logger.error(() -> "Error writing to the config file: " + e.getMessage());
        }
    }


    // Helper method to check for "NULL" and use the default value if needed
    private String getDefaultValue(String value, String defaultValue) {
        return (value == null || NULL_VALUE.equalsIgnoreCase(value)) ? defaultValue : value;
    }

    // Helper to safely parse integers with a default fallback
    private Integer parseIntDefault(String value, int defaultValue) {
        try {
            return (value != null && !NULL_VALUE.equalsIgnoreCase(value)) ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            logger.error(() -> "Error parsing integer value: " + e.getMessage());
            return defaultValue;
        }
    }

    public IntegrityMode getIntegrityMode() {
        return IntegrityMode.valueOf(integrity);
    }


}
