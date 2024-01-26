package Tong_hop;

import javacard.framework.*;

public class Pay extends Applet
{
	private static final byte TOP_UP = (byte) 0x13;
	
	private static final byte PAYMENT  = (byte) 0x14;

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new Pay().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte)0x00:
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

}
