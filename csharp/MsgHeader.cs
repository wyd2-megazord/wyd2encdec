using System;
using System.Runtime.InteropServices;

namespace csharp
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public class MsgHeader
    {
        public UInt16 size_;
        public Byte key_;
        public Byte hash_;
        public UInt16 code_;
        public UInt16 index_;
        public UInt32 timestamp_;
    }

    [Serializable]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
    public class MsgLockPasswordRequest : MsgHeader
    {

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public Byte[] password;
        public Int32 change;
    }
}