package io;

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


    public String readConfigFile(String path) {
        Map<String, String> configMap = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Ignore empty lines or lines without ':' (invalid line format)
                if (!line.contains(":")) continue;

                // Split each line by ":" to separate the key and value
                String[] parts = line.split(":", 2);
                String key = parts[0].trim();
                String value = parts[1].trim();

                // Add the key-value pair to the map, handling "NULL" values
                configMap.put(key, "NULL".equalsIgnoreCase(value) ? null : value);
            }

        } catch (IOException e) {
            System.out.println("Error reading the config file: " + e.getMessage());
        }

        return configMap;

    }

    public String writeConfigFile(String path) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            for (Map.Entry<String, String> entry : configMap.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                // If the value is null, write "NULL", else write the actual value
                if (value == null) {
                    writer.write(key + ": NULL");
                } else {
                    writer.write(key + ": " + value);
                }
                writer.newLine(); // Move to the next line
            }
            System.out.println("Configuration written to " + filePath);
        } catch (IOException e) {
            System.out.println("Error writing to the config file: " + e.getMessage());
        }
    }
}
