using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace csharp
{

    class Program
    {
        public static Byte[] keys;
        public static long sizeEncryptedFile;
        public static Byte[] encryptedFileRaw;
        public static List<MsgHeader> encryptedPackets = new List<MsgHeader>();
        public static long sizeDecryptedFile;
        public static Byte[] decryptedFileRaw;
        public static List<MsgHeader> decryptedPackets = new List<MsgHeader>();

        static void Main(string[] args)
        {
            if (args.Length < 4)
            {
                Environment.Exit(-1);
            }
            if (readKeys(args[0]) == false)
            {
                Environment.Exit(-2);
            }
            if (readData(args[2], ref encryptedFileRaw, encryptedPackets, ref sizeEncryptedFile) == false)
            {
                Environment.Exit(-3);
            }
            if (readData(args[3], ref decryptedFileRaw, decryptedPackets, ref sizeDecryptedFile) == false)
            {
                Environment.Exit(-4);
            }
            if (args[1] == "enc")
            {
                encrypt();
                File.WriteAllBytes("./encoded.bin", decryptedFileRaw);
            }
            if (args[1] == "dec")
            {
                decrypt();
                File.WriteAllBytes("./decoded.bin", encryptedFileRaw);
            }
            int diff = 0;
            for (int i = 0; i < sizeEncryptedFile; i++)
            {
                diff += (encryptedFileRaw[i] != decryptedFileRaw[i] ? 1 : 0);
            }

            Console.WriteLine("{0} differences", diff);

            Environment.Exit(diff);
        }

        static bool readKeys(string filePath)
        {
            try
            {
                keys = File.ReadAllBytes(filePath);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public static unsafe bool readData(string filePath, ref Byte[] fileRaw, List<MsgHeader> packets, ref long size)
        {
            try
            {
                fileRaw = File.ReadAllBytes(filePath);
                size = fileRaw.LongLength;
                for (long offset = 0; offset < size;)
                {
                    MsgHeader packet;
                    fixed (Byte* ptr = &fileRaw[offset])
                    {
                        packet = (MsgHeader)Marshal.PtrToStructure(new IntPtr(ptr), typeof(MsgHeader));
                        if (packet.size_ != 12)
                        {
                            packets.Add(
                                (MsgLockPasswordRequest)Marshal.PtrToStructure(new IntPtr(ptr), typeof(MsgLockPasswordRequest))
                            );
                        }
                        else
                        {
                            packets.Add(packet);
                        }
                    }
                    offset += packet.size_;
                }
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public static unsafe void decrypt()
        {
            long offset = 0;
            foreach (var packet in encryptedPackets)
            {
                Byte[] buffer = new Byte[packet.size_];
                fixed (Byte* ptr = buffer)
                {
                    if (packet.size_ != 12)
                    {
                        Marshal.StructureToPtr<MsgLockPasswordRequest>((MsgLockPasswordRequest)packet, new IntPtr(ptr), true);
                    }
                    else
                    {
                        Marshal.StructureToPtr<MsgHeader>(packet, new IntPtr(ptr), true);
                    }
                }
                Int32 key = (Byte)keys[packet.key_ << 1];
                UInt16 j = 4;
                do
                {
                    UInt32 mappedKey = keys[((key % 256) << 1) + 1];
                    switch (j & 3)
                    {
                        case 0:
                            buffer[j] = (Byte)(buffer[j] - (Byte)(mappedKey << 1));
                            break;
                        case 1:
                            buffer[j] = (Byte)(buffer[j] + (Byte)((int)(mappedKey >> 3)));
                            break;
                        case 2:
                            buffer[j] = (Byte)(buffer[j] - (Byte)(mappedKey << 2));
                            break;
                        case 3:
                            buffer[j] = (Byte)(buffer[j] + (Byte)((int)(mappedKey >> 5)));
                            break;
                    }
                    encryptedFileRaw[offset + j] = buffer[j];
                    j++;
                    key++;
                } while (j < packet.size_);
                offset += j;
            }
        }

        public static unsafe void encrypt()
        {
            long offset = 0;
            foreach (var packet in decryptedPackets)
            {
                Byte[] buffer = new Byte[packet.size_];
                fixed (Byte* ptr = buffer)
                {
                    if (packet.size_ != 12)
                    {
                        Marshal.StructureToPtr<MsgLockPasswordRequest>((MsgLockPasswordRequest)packet, new IntPtr(ptr), true);
                    }
                    else
                    {
                        Marshal.StructureToPtr<MsgHeader>(packet, new IntPtr(ptr), true);
                    }
                }
                Int32 key = (Byte)keys[packet.key_ << 1];
                UInt16 j = 4;
                do
                {
                    UInt32 mappedKey = keys[((key % 256) << 1) + 1];
                    switch (j & 3)
                    {
                        case 0:
                            buffer[j] = (Byte)(buffer[j] + (Byte)(mappedKey << 1));
                            break;
                        case 1:
                            buffer[j] = (Byte)(buffer[j] - (Byte)((int)(mappedKey >> 3)));
                            break;
                        case 2:
                            buffer[j] = (Byte)(buffer[j] + (Byte)(mappedKey << 2));
                            break;
                        case 3:
                            buffer[j] = (Byte)(buffer[j] - (Byte)((int)(mappedKey >> 5)));
                            break;
                    }
                    decryptedFileRaw[offset + j] = buffer[j];
                    j++;
                    key++;
                } while (j < packet.size_);
                offset += j;
            }
        }
    }
}
