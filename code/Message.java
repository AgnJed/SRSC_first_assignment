public class Message {
    private byte[] sequenceNumber;
    private byte[] data;
    private byte[] integrity;

    public Message(byte[] sequenceNumber, byte[] data, byte[] integrity) {
        this.sequenceNumber = sequenceNumber;
        this.data = data;
        this.integrity = integrity;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getIntegrity() {
        return integrity;
    }

    public byte[] getSequenceNumber() {
        return sequenceNumber;
    }

    public byte[] getAll() {
        byte[] all = new byte[sequenceNumber.length + data.length + integrity.length];
        System.arraycopy(sequenceNumber, 0, all, 0, sequenceNumber.length);
        System.arraycopy(data, 0, all, sequenceNumber.length, data.length);
        System.arraycopy(integrity, 0, all, sequenceNumber.length + data.length, integrity.length);
        return all;
    }
}
