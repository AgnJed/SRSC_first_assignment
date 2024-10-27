import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class to read and write the configuration file.
 */
public class FileAccess {

    private static final Logger logger = LoggerFactory.getLogger(FileAccess.class);

    private static final String NULL_VALUE = "NULL";
    private static final String SEPARATOR = ":";

    /**
     * Read the configuration from the file.
     * @param filePath The path to the configuration file.
     * @return The configuration object.
     * TODO the return type could be a Map<String, String> instead of Configuration
     */
    public Configuration readConfigFile(String filePath) {
        Map<String, String> configMap = new HashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.contains(SEPARATOR)) continue;

                List<String> parts = Arrays.stream(line.split(SEPARATOR)).map(String::trim).toList();
                String key = parts.get(0);
                String value = parts.size() == 1 ? null : parts.get(1);

                configMap.put(key, NULL_VALUE.equalsIgnoreCase(value) ? NULL_VALUE : value);
            }
        } catch (IOException e) {
            logger.error(() -> "Error reading the config file: " + e.getMessage());
        }
        return Configuration.parceConfiguration(configMap);
    }

    /**
     * Write the configuration back to the file.
     * @param filePath The path to the configuration file.
     */
    public void writeConfigFile(String filePath, Configuration config) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            for (Map.Entry<String, String> entry : config.toMap().entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue() == null ? NULL_VALUE : entry.getValue();

                writer.write(key + SEPARATOR + value);
                writer.newLine();
            }

        } catch (IOException e) {
            //logger.error(() -> "Error writing the config file: " + e.getMessage());
        }
    }
}
