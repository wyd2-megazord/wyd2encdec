package javaw2;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class PacketInputStream extends ByteArrayInputStream {

    private byte[] tmpBuffer = new byte[8];

    public PacketInputStream(byte[] buf) {
        super(buf);
    }

    public PacketInputStream(byte[] buf, int offset, int length) {
        super(buf, offset, length);
    }

    public synchronized byte readByte() throws IOException {
        read(tmpBuffer, 0, 1);
        return tmpBuffer[0];
    }

    public synchronized boolean readBoolean() throws IOException {
        read(tmpBuffer, 0, 1);
        return (tmpBuffer[0] == 0 ? true : false);
    }

    public synchronized char readChar() throws IOException {
        read(tmpBuffer, 0, 2);

        return (char) ((tmpBuffer[0] & 0xFF) + (tmpBuffer[1] << 8));
    }

    public synchronized short readShort() throws IOException {
        read(tmpBuffer, 0, 2);

        return (short) ((tmpBuffer[0] & 0xFF) + (tmpBuffer[1] << 8));
    }

    public synchronized int readInt() throws IOException {
        read(tmpBuffer, 0, 4);

        return ((tmpBuffer[0] & 0xFF)) + ((tmpBuffer[1] & 0xFF) << 8) + ((tmpBuffer[2] & 0xFF) << 16)
                + ((tmpBuffer[3]) << 24);
    }

    public synchronized float readFloat() throws IOException {
        return Float.intBitsToFloat(readInt());
    }

    public synchronized long readLong() throws IOException {
        read(tmpBuffer, 0, 8);

        return ((tmpBuffer[0] & 0xFFL)) + ((tmpBuffer[1] & 0xFFL) << 8) + ((tmpBuffer[2] & 0xFFL) << 16)
                + ((tmpBuffer[3] & 0xFFL) << 24) + ((tmpBuffer[4] & 0xFFL) << 32) + ((tmpBuffer[5] & 0xFFL) << 40)
                + ((tmpBuffer[6] & 0xFFL) << 48) + (((long) tmpBuffer[7]) << 56);
    }

    public synchronized double readDouble(double val) throws IOException {
        return Double.doubleToLongBits(readLong());
    }

}