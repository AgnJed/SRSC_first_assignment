package test.IO;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.IO.FileAccess;

import static java.IO.FileAccess.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TestFileAccess {

    private FileAccess fileAccess;

    @BeforeEach
    void setUp() {
        fileAccess = new FileAccess();
    }

}