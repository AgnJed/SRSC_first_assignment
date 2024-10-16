import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;

/**
 * Key Service
 */
public class KeyService {

    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_TYPE = "PKCS12";

    /**
     * Gets the public key from the given certificate
     * @param certificatePath The path to the certificate
     * @return The public key
     * @throws Exception If an error occurs.
     */
    public static PublicKey getPublicKeyFromCertificate(String certificatePath) throws Exception {
        FileInputStream fis = new FileInputStream(certificatePath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(fis);
        return cert.getPublicKey();
    }

    /**
     * Gets the private key from the given keystore
     * @param keystorePath The path to the keystore
     * @return The private key
     * @throws Exception If an error occurs.
     */
    public static PrivateKey getPrivateKeyFromKeystore(String keystorePath) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream keystoreStream = new FileInputStream(keystorePath)) {
            keystore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());
        }

        Enumeration<String> aliases = keystore.aliases();
        if (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!aliases.hasMoreElements()) { // Certificando que só existe um alias
                return (PrivateKey) keystore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
            } else {
                throw new Exception("Mais de um alias encontrado no keystore");
            }
        } else {
            throw new Exception("Nenhum alias encontrado no keystore");
        }
    }
}