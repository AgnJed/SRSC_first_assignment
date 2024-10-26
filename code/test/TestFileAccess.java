package test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import io.FileAccess;

import static org.junit.jupiter.api.Assertions.*;

class TestFileAccess {

    private FileAccess fileAccess;

    @BeforeEach
    void setUp() {
        fileAccess = new FileAccess();
    }

    @Test
    void testConfidentialityAlgorithm() {
        fileAccess.setConfidentialityAlgorithm(DEFAULT_CONFIDENTIALITY);
        assertEquals(DEFAULT_CONFIDENTIALITY, fileAccess.getConfidentialityAlgorithm());
    }

    @Test
    void testSymmetricKey() {
        fileAccess.setSymmetricKey(DEFAULT_SYMMETRIC_KEY);
        assertEquals(DEFAULT_SYMMETRIC_KEY, fileAccess.getSymmetricKey());
    }

    @Test
    void testSymmetricKeySize() {
        fileAccess.setSymmetricKeySize(DEFAULT_SYMMETRIC_KEY_SIZE);
        assertEquals(DEFAULT_SYMMETRIC_KEY_SIZE, fileAccess.getSymmetricKeySize());
    }

    @Test
    void testIvSize() {
        fileAccess.setIvSize(DEFAULT_IV_SIZE);
        assertEquals(DEFAULT_IV_SIZE, fileAccess.getIvSize());
    }

    @Test
    void testIv() {
        fileAccess.setIv(DEFAULT_IV);
        assertEquals(DEFAULT_IV, fileAccess.getIv());
    }

    @Test
    void testIntegrity() {
        fileAccess.setIntegrity(DEFAULT_INTEGRITY);
        assertEquals(DEFAULT_INTEGRITY, fileAccess.getIntegrity());
    }

    @Test
    void testH() {
        fileAccess.setH(DEFAULT_H);
        assertEquals(DEFAULT_H, fileAccess.getH());
    }

    @Test
    void testMac() {
        fileAccess.setMac(DEFAULT_MAC);
        assertEquals(DEFAULT_MAC, fileAccess.getMac());
    }

    @Test
    void testMacKey() {
        fileAccess.setMacKey(DEFAULT_MAC_KEY);
        assertEquals(DEFAULT_MAC_KEY, fileAccess.getMacKey());
    }

    @Test
    void testMacKeySize() {
        fileAccess.setMacKeySize(DEFAULT_MAC_KEY_SIZE);
        assertEquals(DEFAULT_MAC_KEY_SIZE, fileAccess.getMacKeySize());
    }
}