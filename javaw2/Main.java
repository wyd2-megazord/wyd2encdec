package javaw2;

import java.util.ArrayList;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Main {

    public static byte[] keys = new byte[512];
    public static long sizeEncryptedFile;
    public static byte[] encryptedFileRaw;
    public static List<MsgHeader> encryptedPackets = new ArrayList<MsgHeader>();
    public static long sizeDecryptedFile;
    public static byte[] decryptedFileRaw;
    public static List<MsgHeader> decryptedPackets = new ArrayList<MsgHeader>();

    public static void main(String[] args) {
        if (args.length < 4) {
            System.exit(-1);
        }
        if (readKeys(args[0]) == false) {
            System.exit(-2);
        }
        if ((sizeEncryptedFile = readData(args[2], true, encryptedPackets)) == 0) {
            System.exit(-3);
        }
        if ((sizeDecryptedFile = readData(args[3], false, decryptedPackets)) == 0) {
            System.exit(-4);
        }
        if (args[1].equals("enc")) {
            encrypt();
            writeData("./encoded.bin", decryptedFileRaw);
        }
        if (args[1].equals("dec")) {
            decrypt();
            writeData("./decoded.bin", encryptedFileRaw);
        }
        int diff = 0;
        for (int i = 0; i < sizeEncryptedFile; i++) {
            diff += (encryptedFileRaw[i] != decryptedFileRaw[i] ? 1 : 0);
        }

        System.out.printf("%d differences\n", diff);

        System.exit(diff);
    }

    public static boolean readKeys(String filePath) {
        try {
            FileInputStream file = new FileInputStream(filePath);
            file.read(keys);
            file.close();
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    public static void preparePackets(byte[] buffer, int size, List<MsgHeader> packets) {

        try {
            PacketInputStream bis = new PacketInputStream(buffer);
            int i = 0;
            while (i < size) {
                bis.mark(i);
                MsgHeader packet = new MsgHeader();
                packet.readObject(bis);
                if (packet.size_ != 12) {
                    packet = new MsgLockPasswordRequest();
                    bis.reset();
                    packet.readObject(bis);
                }
                packets.add(packet);
                i += packet.size_;
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static void writeData(String filePath, byte[] buffer) {
        try {
            File file = new File(filePath);
            FileOutputStream fileStream = new FileOutputStream(file);
            fileStream.write(buffer);
            fileStream.close();
        } catch (Exception e) {
        }
    }

    public static long readData(String filePath, boolean encrypted, List<MsgHeader> packets) {
        int size = 0;
        try {
            File file = new File(filePath);
            FileInputStream fileStream = new FileInputStream(file);
            size = (int) file.length();
            if (encrypted) {
                encryptedFileRaw = new byte[size];
                fileStream.read(encryptedFileRaw);
                fileStream.close();
                preparePackets(encryptedFileRaw, size, packets);
            } else {
                decryptedFileRaw = new byte[size];
                fileStream.read(decryptedFileRaw);
                fileStream.close();
                preparePackets(decryptedFileRaw, size, packets);
            }
        } catch (Exception e) {
            System.out.println(e);
        }
        return (long) size;
    }

    public static void decrypt() {
        int offset = 0;
        for (MsgHeader packet : encryptedPackets) {
            try {
                PacketOutputStream pos = new PacketOutputStream();
                packet.writeObject(pos);
                byte[] buffer = pos.toByteArray();
                pos.flush();
                int key = (int) (keys[(int) (packet.key_ & 0xFF) << 1] & 0xFF);
                short j = 4;
                do {
                    int mappedKey = (int) (keys[((key % 256) << 1) + 1] & 0xFF);
                    switch (j & 3) {
                        case 0:
                            buffer[j] = (byte) (buffer[j] - (byte) (mappedKey << 1));
                            break;
                        case 1:
                            buffer[j] = (byte) (buffer[j] + (byte) ((int) (mappedKey >>> 3)));
                            break;
                        case 2:
                            buffer[j] = (byte) (buffer[j] - (byte) (mappedKey << 2));
                            break;
                        case 3:
                            buffer[j] = (byte) (buffer[j] + (byte) ((int) (mappedKey >>> 5)));
                            break;
                    }
                    encryptedFileRaw[offset + j] = buffer[j];
                    j++;
                    key++;
                } while (j < packet.size_);
                offset += j;
            } catch (Exception e) {
            }
        }
    }

    public static void encrypt() {
        int offset = 0;
        for (MsgHeader packet : decryptedPackets) {
            try {
                PacketOutputStream pos = new PacketOutputStream();
                packet.writeObject(pos);
                byte[] buffer = pos.toByteArray();
                pos.flush();
                int key = (byte) keys[packet.key_ << 1];
                short j = 4;
                do {
                    int mappedKey = keys[((key % 256) << 1) + 1];
                    switch (j & 3) {
                        case 0:
                            buffer[j] = (byte) (buffer[j] + (byte) (mappedKey << 1));
                            break;
                        case 1:
                            buffer[j] = (byte) (buffer[j] - (byte) ((int) (mappedKey >>> 3)));
                            break;
                        case 2:
                            buffer[j] = (byte) (buffer[j] + (byte) (mappedKey << 2));
                            break;
                        case 3:
                            buffer[j] = (byte) (buffer[j] - (byte) ((int) (mappedKey >>> 5)));
                            break;
                    }
                    decryptedFileRaw[offset + j] = buffer[j];
                    j++;
                    key++;
                } while (j < packet.size_);
                offset += j;
            } catch (Exception e) {
            }
        }
    }
}