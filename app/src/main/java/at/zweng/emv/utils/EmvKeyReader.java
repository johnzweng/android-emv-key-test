package at.zweng.emv.utils;

import at.zweng.emv.keys.CaPublicKey;
import at.zweng.emv.keys.IssuerPublicKey;
import fr.devnied.bitlib.BitUtils;
import fr.devnied.bitlib.BytesUtils;
import org.apache.commons.lang3.time.DateUtils;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

import static at.zweng.emv.utils.EmvUtils.calculateSHA1;
import static at.zweng.emv.utils.EmvUtils.getUnsignedBytes;

/**
 * @author Johannes Zweng (johannes@zweng.at) on 23.10.17.
 */
public class EmvKeyReader {

    // EMV Book 2 (v4.3)
    // https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_2_Security_and_Key_Management_20120607061923900.pdf

    /**
     * Parse the issuer public key.
     * See EMV (v4.3) Book 2, table 13 for Issuer public key certificate format.
     *
     * @param caPublicKey          Global card scheme (i.e. Mastercard, VISA, ..) CA public key
     * @param publicKeyCertificate issuer public key certificate as read from card
     * @param remainingBytes       remaining modulus bytes as read from card
     * @param publicKeyExponent    public key exponent as read from card
     * @return the issuer public key
     */
    public IssuerPublicKey parseIssuerPublicKey(CaPublicKey caPublicKey, byte[] publicKeyCertificate,
                                                byte[] remainingBytes, byte[] publicKeyExponent)
            throws EmvParsingException {

        byte[] recoveredBytes = calculateRSA(publicKeyCertificate, caPublicKey.getPublicExponent(), caPublicKey.getModulus());
        final RecoveredIssuerPublicKey cert = this.parseIssuerPublicKeyCert(recoveredBytes, getUnsignedBytes(caPublicKey.getModulus()).length);
        Date expirationDate = parseDate(cert.certExpirationDate);
        if (cert.issuerPublicKeyExponentLength != publicKeyExponent.length) {
            throw new EmvParsingException(String.format("Issuer public key exponent has incorrect length. Should be %d"
                    + " but we got %d.", cert.issuerPublicKeyExponentLength, publicKeyExponent.length));
        }

        // concatenate the leftmost part of modulus (recovered from certificate) plus
        // the remainder bytes
        byte[] completeModulus = new byte[cert.leftMostPubKeyDigits.length + remainingBytes.length];
        System.arraycopy(cert.leftMostPubKeyDigits, 0, completeModulus, 0, cert.leftMostPubKeyDigits.length);
        System.arraycopy(remainingBytes, 0, completeModulus, cert.leftMostPubKeyDigits.length, remainingBytes.length);

        return new IssuerPublicKey(new BigInteger(1, publicKeyExponent),
                new BigInteger(1, completeModulus), publicKeyCertificate, expirationDate);
    }


    /**
     * Check if cert is valid and if the calculated hash matches the hash in the certificate
     *
     * @param caPublicKey          used public key of card-system Root CA
     * @param publicKeyCertificate issuer public key cert as read from card
     * @param remainingBytes       remaining bytes of issuer public key as read from card
     * @param publicKeyExponent    exponent of issuer public key as read from card
     * @return true if validation is successful, false otherwise
     * @throws EmvParsingException
     */
    public boolean validateIssuerPublicKey(CaPublicKey caPublicKey, byte[] publicKeyCertificate,
                                           byte[] remainingBytes, byte[] publicKeyExponent) throws EmvParsingException {
        byte[] recoveredBytes = calculateRSA(publicKeyCertificate, caPublicKey.getPublicExponent(), caPublicKey.getModulus());
        final RecoveredIssuerPublicKey cert = this.parseIssuerPublicKeyCert(recoveredBytes, getUnsignedBytes(caPublicKey.getModulus()).length);

        ByteArrayOutputStream hashStream = new ByteArrayOutputStream();
        // calculate our own hash for comparison:
        hashStream.write(cert.certificateFormat);
        hashStream.write(cert.issuerIdentifier, 0, cert.issuerIdentifier.length);
        hashStream.write(cert.certExpirationDate, 0, cert.certExpirationDate.length);
        hashStream.write(cert.certSerialNumber, 0, cert.certSerialNumber.length);
        hashStream.write((byte) cert.hashAlgoIndicator);
        hashStream.write((byte) cert.issuerPubKeyAlgoIndicator);
        hashStream.write((byte) cert.issuerPublicKeyLength);
        hashStream.write((byte) cert.issuerPublicKeyExponentLength);
        hashStream.write(cert.leftMostPubKeyDigits, 0, cert.leftMostPubKeyDigits.length);
        hashStream.write(remainingBytes, 0, remainingBytes.length);
        hashStream.write(publicKeyExponent, 0, publicKeyExponent.length);
        // calculate hash:
        byte[] calculatedHash = calculateSHA1(hashStream.toByteArray());
        // compare it with value in cert:
        return Arrays.equals(calculatedHash, cert.hashResult);
    }


    /**
     * https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_2_Security_and_Key_Management_20120607061923900.pdf
     *
     * EMV spec 4.3, Book 2, table 13:
     * "Format of Data Recovered from Issuer Public Key Certificate":
     *
     * Field Name                         Length   Description
     * Recovered Data Header                 1     Hex value '6A'
     * Certificate Format                    1     Hex value '02'
     * Issuer Identifier                     4     Leftmost 3-8 digits from the PAN (padded to the right with
     * Hex 'F's)
     * Certificate Expiration Date           2     MMYY after which this certificate is invalid (BCD format)
     * Certificate Serial Number             3     Binary number unique to this certificate assigned by the CA
     * Hash Algorithm Indicator              1     Identifies the hash algorithm used to produce the Hash Result
     * in the digital signature scheme (only 0x01 = SHA-1 allowed)
     * Issuer Public Key Algorithm Indicator 1     Identifies the digital signature algorithm
     * (only 0x01 = RSA allowed)
     * Issuer Public Key Length              1     length of the Issuer Public Key Modulus in bytes
     * Issuer Public Key Exponent Length     1     length of the Issuer Public Key Exponent in bytes
     * Issuer Public Key or Leftmost
     * Digits of the Issuer Public Key    nCA–36   If nI ≤ nCA – 36, consists of the full Issuer Public Key padded
     * to the right with nCA–36–nI bytes of value 'BB' If nI > nCA – 36,
     * consists of the nCA – 36 most significant bytes of the Issuer Public Key
     * Hash Result                           20    Hash of the Issuer Public Key and its related information
     * Recovered Data Trailer                1     Hex value 'BC' b
     */
    private class RecoveredIssuerPublicKey {
        int recoveredDataHeader;
        int certificateFormat;
        byte[] issuerIdentifier;
        byte[] certExpirationDate;
        byte[] certSerialNumber;
        int hashAlgoIndicator;
        int issuerPubKeyAlgoIndicator;
        int issuerPublicKeyLength;
        int issuerPublicKeyExponentLength;
        byte[] leftMostPubKeyDigits;
        byte[] optionalPadding;
        byte[] hashResult;
        int dataTrailer;
    }

    /**
     * Parse the recovered issuer public key certificate bytes.
     *
     * @param recoveredBytes  recovered bytes after RSA
     * @param caModulusLength length of CA pubkey modulus
     * @return parsed data
     * @throws EmvParsingException
     */
    private RecoveredIssuerPublicKey parseIssuerPublicKeyCert(byte[] recoveredBytes, int caModulusLength) throws EmvParsingException {
        RecoveredIssuerPublicKey r = new RecoveredIssuerPublicKey();
        BitUtils bits = new BitUtils(recoveredBytes);

        r.recoveredDataHeader = bits.getNextInteger(8);
        if (r.recoveredDataHeader != 0x6a) {
            throw new EmvParsingException("Certificate started with incorrect header: "
                    + Integer.toHexString(r.recoveredDataHeader));
        }
        r.certificateFormat = bits.getNextInteger(8);
        if (r.certificateFormat != 0x02) {
            throw new EmvParsingException("Certificate Format is unknown: " + Integer.toHexString(r.certificateFormat));
        }
        r.issuerIdentifier = bits.getNextByte(32);
        r.certExpirationDate = bits.getNextByte(16);
        r.certSerialNumber = bits.getNextByte(24);
        // as of EMV 4.3 spec only "0x01" (= SHA-1) is specified
        r.hashAlgoIndicator = bits.getNextInteger(8);
        if (r.hashAlgoIndicator != 0x01) {
            throw new EmvParsingException("Hash Algorithm Indicator is invalid. Only 0x01 is allowed. We found: "
                    + Integer.toHexString(r.hashAlgoIndicator));
        }
        // as of EMV 4.3 spec only "0x01" (= RSA) is specified
        r.issuerPubKeyAlgoIndicator = bits.getNextInteger(8);
        if (r.issuerPubKeyAlgoIndicator != 0x01) {
            throw new EmvParsingException("Issuer Publuc Key Algorithm Indicator is invalid. Only 0x01 is allowed. "
                    + "We found: " + Integer.toHexString(r.issuerPubKeyAlgoIndicator));
        }
        r.issuerPublicKeyLength = bits.getNextInteger(8);
        r.issuerPublicKeyExponentLength = bits.getNextInteger(8);
        // johnzweng: according to EMV book 2 length of modulus bytes is length of CA modulus - 36
        // CA modulus length must be the same length as this certificate (this is property of RSA)
        int numberOfModulusBytesInCert = caModulusLength - 36;
        int paddingLength = 0; // # of padding bytes if nC<nCA-36
        if (r.issuerPublicKeyLength < numberOfModulusBytesInCert) {
            // in this case we have padding bytes, store the number of padding bytes
            paddingLength = numberOfModulusBytesInCert - r.issuerPublicKeyLength;
            numberOfModulusBytesInCert = r.issuerPublicKeyLength;
        }

        r.leftMostPubKeyDigits = bits.getNextByte(numberOfModulusBytesInCert * 8);
        // if we have padding bytes, skip them (not used)
        if (paddingLength > 0) {
            r.optionalPadding = bits.getNextByte(paddingLength * 8);
        } else {
            r.optionalPadding = new byte[0];
        }
        r.hashResult = bits.getNextByte(20 * 8);
        r.dataTrailer = bits.getNextInteger(8);
        if (r.dataTrailer != 0xbc) {//Trailer
            throw new EmvParsingException("Certificate ended with incorrect trailer: " +
                    Integer.toHexString(r.dataTrailer));
        }
        if (bits.getCurrentBitIndex() != bits.getSize()) {
            throw new EmvParsingException("There are bytes left in certificate after we have read all data.");
        }
        return r;
    }


    /**
     * Parse date value from 2 byte value
     *
     * @param dateBytes 2 bytes, containing YYMM as BCD-formatted digits
     * @return parsed date value
     * @throws EmvParsingException
     */
    private static Date parseDate(byte[] dateBytes) throws EmvParsingException {
        if (dateBytes == null || dateBytes.length != 2) {
            throw new EmvParsingException("Date value must be exact 2 bytes long.");
        }
        SimpleDateFormat sdf = new SimpleDateFormat("MMyy", Locale.getDefault());
        try {
            Date parsedDate = sdf.parse(BytesUtils.bytesToStringNoSpace(dateBytes));
            final Calendar calendar = Calendar.getInstance();
            calendar.setTime(parsedDate);
            int lastDayOfExpiryMonth = calendar.getActualMaximum(Calendar.DAY_OF_MONTH);
            return DateUtils.setDays(parsedDate, lastDayOfExpiryMonth);
        } catch (ParseException e) {
            throw new EmvParsingException("Unparsable date: " + BytesUtils.bytesToStringNoSpace(dateBytes), e);
        }
    }


    /**
     * Manually perform RSA operation: data ^ exponent mod modulus
     *
     * @param data     data bytes to operate on
     * @param exponent exponent
     * @param modulus  modulus
     * @return data ^ exponent mod modulus
     */
    private static byte[] calculateRSA(byte[] data, BigInteger exponent, BigInteger modulus) throws EmvParsingException {
        // bigInts here are unsigned:
        BigInteger dataBigInt = new BigInteger(1, data);

        return getUnsignedBytes(dataBigInt.modPow(exponent, modulus));
    }
    
    /*

        Validate:
     byte[] hash = new byte[20];
     bis.read(hash, 0, hash.length);

     ByteArrayOutputStream hashStream = new ByteArrayOutputStream();
     // calculate our own hash for comparison:
     hashStream.write(certFormat);
     hashStream.write(issuerIdentifierPaddedBytes, 0, issuerIdentifierPaddedBytes.length);
     hashStream.write(certExpirationDate, 0, certExpirationDate.length);
     hashStream.write(certSerialNumber, 0, certSerialNumber.length);
     hashStream.write((byte) hashAlgorithmIndicator);
     hashStream.write((byte) issuerPublicKeyAlgorithmIndicator);
     hashStream.write((byte) issuerPublicKeyModLengthTotal);
     hashStream.write((byte) issuerPublicKeyExpLengthTotal);
     hashStream.write(leftMostModulusBytes);
     hashStream.write(issuerPublicKeyRemainder);
     hashStream.write(issuerPublicKeyExponent);

     byte[] sha1Result = null;
     try {
     sha1Result = Util.calculateSHA1(hashStream.toByteArray());
     } catch (NoSuchAlgorithmException ex) {
     throw new SignedDataException("SHA-1 hash algorithm not available", ex);
     }

     if (!Arrays.equals(sha1Result, hash)) {
     throw new SignedDataException("Hash is not valid");
     }


     */

}
