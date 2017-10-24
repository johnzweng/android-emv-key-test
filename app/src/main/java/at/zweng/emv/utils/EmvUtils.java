package at.zweng.emv.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class EmvUtils {

    /**
     * Calculate sha-1
     *
     * @param data data
     * @return sha-1 hash values
     * @throws EmvParsingException
     */
    public static byte[] calculateSHA1(byte[] data) throws EmvParsingException {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new EmvParsingException("No such algorithm: SHA-1", e);
        }
        return md.digest(data);
    }


    /**
     * Get a byte[] representation for an unsigned BigInteger without the leading 0x00 byte, representing sign.
     *
     * @param bigint
     * @return byte array representation
     * @throws EmvParsingException if called with a negative BigInteger
     */
    public static byte[] getUnsignedBytes(BigInteger bigint) throws EmvParsingException {
        if (bigint.compareTo(new BigInteger("0")) < 0) {
            throw new EmvParsingException("Cannot get unsigned bytes for signed BigInteger.");
        }
        final byte[] signedBytes = bigint.toByteArray();
        if (signedBytes[0] == 0x00) {
            return Arrays.copyOfRange(signedBytes, 1, signedBytes.length);
        }
        return signedBytes;
    }

}
