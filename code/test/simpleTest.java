package test;

import org.junit.jupiter.api.Test;

import java.IO.FileAccess;

import static org.junit.jupiter.api.Assertions.*;

public class simpleTest {
    @Test
    public void test() {
        FileAccess fileAccess = new FileAccess();
        String read = fileAccess.readConfigFile("path");
        assertEquals("abc", read);
        assertTrue(true);
        assertNotEquals(1, 2);
    }
}
