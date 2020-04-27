package javaw2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public class MsgHeader {

    public short size_;
    public byte key_;
    public byte hash_;
    public short code_;
    public short index_;
    public int timestamp_;

    public void readObject(PacketInputStream aInputStream)
            throws IOException, IllegalArgumentException, IllegalAccessException {
        List<Class> classes = new ArrayList<>();
        Class current = this.getClass();
        if (current.getSuperclass() != null) {
            classes.add(current.getSuperclass());
        }
        classes.add(current);
        for (Class c : classes) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == byte.class) {
                    f.setByte(this, aInputStream.readByte());
                } else if (f.getType() == short.class) {
                    f.setShort(this, aInputStream.readShort());
                } else if (f.getType() == int.class) {
                    f.setInt(this, aInputStream.readInt());
                } else if (f.getType().isArray()) {
                    if (f.getType().getComponentType() == byte.class) {
                        byte[] _arr = (byte[]) f.get(this);
                        aInputStream.read(_arr, 0, Array.getLength(_arr));
                    }
                }
            }
        }
    }

    public void writeObject(PacketOutputStream aOutputStream)
            throws IOException, IllegalArgumentException, IllegalAccessException {
        List<Class> classes = new ArrayList<>();
        Class current = this.getClass();
        if (current.getSuperclass() != null) {
            classes.add(current.getSuperclass());
        }
        classes.add(current);
        for (Class c : classes) {
            for (Field f : c.getDeclaredFields()) {
                if (f.getType() == byte.class) {
                    aOutputStream.putByte((byte) f.get(this));
                } else if (f.getType() == short.class) {
                    aOutputStream.putShort((short) f.get(this));
                } else if (f.getType() == int.class) {
                    aOutputStream.putInt((int) f.get(this));
                } else if (f.getType().isArray()) {
                    if (f.getType().getComponentType() == byte.class) {
                        aOutputStream.write((byte[]) f.get(this));
                    }
                }
            }
        }
    }
}