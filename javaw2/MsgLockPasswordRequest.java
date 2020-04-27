package javaw2;

public class MsgLockPasswordRequest extends MsgHeader {
    final public byte[] password = new byte[16];
    public int change;
}