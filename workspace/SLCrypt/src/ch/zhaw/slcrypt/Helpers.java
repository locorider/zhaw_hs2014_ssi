package ch.zhaw.slcrypt;

/**
 * The Helpers class contains a collection of useful helpers.
 */
public class Helpers {

	/**
	 * Returns the hexadecimal representation of the elements in a byte array.
	 * 
	 * @param buf
	 *            The byte array to convert
	 * @return The hexadecimal representation as a String
	 */
	public static String asHex(byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10) {
				strbuf.append("0");
			}
			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}
		return strbuf.toString();
	}
}