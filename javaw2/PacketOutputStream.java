package javaw2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class PacketOutputStream extends ByteArrayOutputStream {

    private byte[] byteBuffer = new byte[1];
    private byte[] shortBuffer = new byte[2];
    private byte[] intBuffer = new byte[4];
    private byte[] longBuffer = new byte[8];

    public synchronized void putByte(byte val) throws IOException {
        byteBuffer[0] = (byte) (val >>> 8);
        write(byteBuffer);
    }

    public synchronized void putBoolean(boolean val) throws IOException {
        byteBuffer[0] = (byte) (val ? 1 : 0);
        write(byteBuffer);
    }

    public synchronized void putChar(char val) throws IOException {
        shortBuffer[1] = (byte) (val >>> 8);
        shortBuffer[0] = (byte) (val);
        write(shortBuffer);
    }

    public synchronized void putShort(short val) throws IOException {
        shortBuffer[1] = (byte) (val >>> 8);
        shortBuffer[0] = (byte) (val);
        write(shortBuffer);
    }

    public synchronized void putInt(int val) throws IOException {
        intBuffer[3] = (byte) (val >>> 24);
        intBuffer[2] = (byte) (val >>> 16);
        intBuffer[1] = (byte) (val >>> 8);
        intBuffer[0] = (byte) (val);
        write(intBuffer);
    }

    public synchronized void putFloat(float val) throws IOException {
        putInt(Float.floatToIntBits(val));
    }

    public synchronized void putLong(long val) throws IOException {
        longBuffer[7] = (byte) (val >>> 56);
        longBuffer[6] = (byte) (val >>> 48);
        longBuffer[5] = (byte) (val >>> 40);
        longBuffer[4] = (byte) (val >>> 32);
        longBuffer[3] = (byte) (val >>> 24);
        longBuffer[2] = (byte) (val >>> 16);
        longBuffer[1] = (byte) (val >>> 8);
        longBuffer[0] = (byte) (val);
        write(longBuffer);
    }

    public synchronized void putDouble(double val) throws IOException {
        putLong(Double.doubleToLongBits(val));
    }

}