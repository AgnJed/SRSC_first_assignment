package java.service;

public enum Mode {
    CONFIDENTIALIY("CONFIDENTIALIY"), SENDER("something");

    Mode(String something) {
        Mode.valueOf(something);
    }
}
