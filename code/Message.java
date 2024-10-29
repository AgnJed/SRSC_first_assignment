
public record Message(byte[] sequenceNumber, byte[] data, byte[] integrity) {

    public byte[] getAll() {
        byte[] all = new byte[sequenceNumber.length + data.length + integrity.length];
        System.arraycopy(sequenceNumber, 0, all, 0, sequenceNumber.length);
        System.arraycopy(data, 0, all, sequenceNumber.length, data.length);
        System.arraycopy(integrity, 0, all, sequenceNumber.length + data.length, integrity.length);
        return all;
    }
}
