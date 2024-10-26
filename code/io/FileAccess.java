package java.IO;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class FileAccess {

//    CONFIDENTIALIY: ALG/MODE/PADDING
//    SYMMETRIC_KEY: key in hexadecimal value with the required key size
//    SYMMTRIC_KEY_SIZE: integer representing the  number of BITS
//    IV Size: integer or NULL
//    IV: hexadecimal value or NULL
//    INTEGRITY: HMAC or H
//    H: definition of secure ash Function or NULL
//    MAC: definition of MAC (HMAC or CMAC algorithms)
//    MACKEY: mackey value in hexadecimal with rquired keysize or NULL
//    MACKEY_SIZE: integer representing the size of the MACKEY in BITS

    // Getters and Setters for each configuration

    private String confidentialityAlgorithm;
    private String symmetricKey;
    private Integer symmetricKeySize;
    private Integer ivSize;
    private String iv;
    private String integrity;
    private String h;
    private String mac;
    private String macKey;
    private Integer macKeySize;

    // Default values for each field
    private static final String DEFAULT_CONFIDENTIALITY = "AES/CBC/PKCS5Padding";
    private static final String DEFAULT_SYMMETRIC_KEY = "00112233445566778899AABBCCDDEEFF";
    private static final int DEFAULT_SYMMETRIC_KEY_SIZE = 128;
    private static final int DEFAULT_IV_SIZE = 16;
    private static final String DEFAULT_IV = "0000000000000000";
    private static final String DEFAULT_INTEGRITY = "HMAC";
    private static final String DEFAULT_H = "SHA-256";
    private static final String DEFAULT_MAC = "HMAC-SHA256";
    private static final String DEFAULT_MAC_KEY = "A1B2C3D4E5F60708";
    private static final int DEFAULT_MAC_KEY_SIZE = 128;

    private static final String CONFIG_FILE_NAME = "testConfig.txt";

    public String getConfidentialityAlgorithm() {
        return confidentialityAlgorithm;
    }

    public void setConfidentialityAlgorithm(String confidentialityAlgorithm) {
        this.confidentialityAlgorithm = confidentialityAlgorithm;
    }

    public String getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(String symmetricKey) {
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

    public String getMacKey() {
        return macKey;
    }

    public void setMacKey(String macKey) {
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

                configMap.put(key, "NULL".equalsIgnoreCase(value) ? null : value);
            }

            // Set fields, checking for "NULL" and using defaults if necessary
            setConfidentialityAlgorithm(getDefaultValue(configMap.get("CONFIDENTIALITY"), DEFAULT_CONFIDENTIALITY));
            setSymmetricKey(getDefaultValue(configMap.get("SYMMETRIC_KEY"), DEFAULT_SYMMETRIC_KEY));
            setSymmetricKeySize(parseIntDefault(configMap.get("SYMMETRIC_KEY_SIZE"), DEFAULT_SYMMETRIC_KEY_SIZE));
            setIvSize(parseIntDefault(configMap.get("IV Size"), DEFAULT_IV_SIZE));
            setIv(getDefaultValue(configMap.get("IV"), DEFAULT_IV));
            setIntegrity(getDefaultValue(configMap.get("INTEGRITY"), DEFAULT_INTEGRITY));
            setH(getDefaultValue(configMap.get("H"), DEFAULT_H));
            setMac(getDefaultValue(configMap.get("MAC"), DEFAULT_MAC));
            setMacKey(getDefaultValue(configMap.get("MACKEY"), DEFAULT_MAC_KEY));
            setMacKeySize(parseIntDefault(configMap.get("MACKEY_SIZE"), DEFAULT_MAC_KEY_SIZE));

        } catch (IOException e) {
            System.out.println("Error reading the config file: " + e.getMessage());
        }
    }

         // Helper method to check for "NULL" and use the default value if needed
    private String getDefaultValue(String value, String defaultValue) {
        return (value == null || "NULL".equalsIgnoreCase(value)) ? defaultValue : value;
    }


    // Helper to safely parse integers with a default fallback
    private Integer parseIntDefault(String value, int defaultValue) {
        try {
            return (value != null && !"NULL".equalsIgnoreCase(value)) ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            System.out.println("Invalid integer format: " + value);
            return defaultValue;
        }
    }

}

