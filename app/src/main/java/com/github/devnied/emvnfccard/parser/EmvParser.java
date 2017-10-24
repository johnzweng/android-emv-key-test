/*
 * Copyright (C) 2013 MILLAU Julien
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.devnied.emvnfccard.parser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.devnied.emvnfccard.enums.CommandEnum;
import com.github.devnied.emvnfccard.enums.EmvCardScheme;
import com.github.devnied.emvnfccard.enums.SwEnum;
import com.github.devnied.emvnfccard.exception.CommunicationException;
import com.github.devnied.emvnfccard.iso7816emv.EmvTags;
import com.github.devnied.emvnfccard.iso7816emv.EmvTerminal;
import com.github.devnied.emvnfccard.iso7816emv.TLV;
import com.github.devnied.emvnfccard.iso7816emv.TagAndLength;
import com.github.devnied.emvnfccard.model.Afl;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.model.EmvTransactionRecord;
import com.github.devnied.emvnfccard.model.enums.CurrencyEnum;
import com.github.devnied.emvnfccard.utils.CommandApdu;
import com.github.devnied.emvnfccard.utils.ResponseUtils;
import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.github.devnied.emvnfccard.utils.TrackUtils;

import fr.devnied.bitlib.BytesUtils;
import fr.devnied.bitlib.BitUtils;

/**
 * Emv Parser.<br/>
 * Class used to read and parse EMV card
 *
 * @author MILLAU Julien
 *
 */
public class EmvParser {

    /**
     * Class Logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EmvParser.class);

    /**
     * PPSE directory "2PAY.SYS.DDF01"
     */
    private static final byte[] PPSE = "2PAY.SYS.DDF01".getBytes();

    /**
     * PSE directory "1PAY.SYS.DDF01"
     */
    private static final byte[] PSE = "1PAY.SYS.DDF01".getBytes();

    /**
     * Unknow response
     */
    public static final int UNKNOW = -1;

    /**
     * Card holder name separator
     */
    public static final String CARD_HOLDER_NAME_SEPARATOR = "/";

    /**
     * Provider
     */
    private IProvider provider;

    /**
     * use contact less mode
     */
    private boolean contactLess;

    /**
     * Card data
     */
    private EmvCard card;

    /**
     * Constructor
     *
	 * @param pProvider
	 *            provider to launch command
	 * @param pContactLess
	 *            boolean to indicate if the EMV card is contact less or not
     */
    public EmvParser(final IProvider pProvider, final boolean pContactLess) {
        provider = pProvider;
        contactLess = pContactLess;
        card = new EmvCard();
    }

    /**
     * Method used to read public data from EMV card
     *
     * @return data read from card or null if any provider match the card type
     */
    public EmvCard readEmvCard() throws CommunicationException {
        // use PSE first
        if (!readWithPSE()) {
            // Find with AID
            readWithAID();
        }
        return card;
    }

    /**
     * Method used to select payment environment PSE or PPSE
     *
     * @return response byte array
     * @throws CommunicationException
     */
    protected byte[] selectPaymentEnvironment() throws CommunicationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Select " + (contactLess ? "PPSE" : "PSE") + " Application");
        }
        // Select the PPSE or PSE directory
        return provider.transceive(new CommandApdu(CommandEnum.SELECT, contactLess ? PPSE : PSE, 0).toBytes());
    }

    /**
     * Method used to get the number of pin try left
     *
     * @return the number of pin try left
     * @throws CommunicationException
     */
    protected int getLeftPinTry() throws CommunicationException {
        int ret = UNKNOW;
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Get Left PIN try");
        }
        // Left PIN try command
        byte[] data = provider.transceive(new CommandApdu(CommandEnum.GET_DATA, 0x9F, 0x17, 0).toBytes());
        if (ResponseUtils.isSucceed(data)) {
            // Extract PIN try counter
            byte[] val = TlvUtil.getValue(data, EmvTags.PIN_TRY_COUNTER);
            if (val != null) {
                ret = BytesUtils.byteArrayToInt(val);
            }
        }
        return ret;
    }

    /**
     * Method used to parse FCI Proprietary Template
     *
	 * @param pData
	 *            data to parse
     * @return
     * @throws CommunicationException
     */
    protected byte[] parseFCIProprietaryTemplate(final byte[] pData) throws CommunicationException {
        // Get SFI
        byte[] data = TlvUtil.getValue(pData, EmvTags.SFI);

        // Check SFI
        if (data != null) {
            int sfi = BytesUtils.byteArrayToInt(data);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("SFI found:" + sfi);
            }
            data = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, sfi, sfi << 3 | 4, 0).toBytes());
            // If LE is not correct
            if (ResponseUtils.isEquals(data, SwEnum.SW_6C)) {
                data = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, sfi, sfi << 3 | 4, data[data.length - 1]).toBytes());
            }
            return data;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("(FCI) Issuer Discretionary Data is already present");
        }
        return pData;
    }

    /**
     * Method used to extract application label
     *
     * @return decoded application label or null
     */
    protected String extractApplicationLabel(final byte[] pData) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Extract Application label");
        }
        String label = null;
        byte[] labelByte = TlvUtil.getValue(pData, EmvTags.APPLICATION_LABEL);
        if (labelByte != null) {
            label = new String(labelByte);
        }
        return label;
    }

    /**
     * Read EMV card with Payment System Environment or Proximity Payment System
     * Environment
     *
     * @return true is succeed false otherwise
     */
    protected boolean readWithPSE() throws CommunicationException {
        boolean ret = false;
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Try to read card with Payment System Environment");
        }
        // Select the PPSE or PSE directory
        byte[] data = selectPaymentEnvironment();
        if (ResponseUtils.isSucceed(data)) {
            // Parse FCI Template
            data = parseFCIProprietaryTemplate(data);
            // Extract application label
            if (ResponseUtils.isSucceed(data)) {
                // Get Aids
                List<byte[]> aids = getAids(data);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Payment System Environment contained " + aids.size() + " aid entries.");
                }
                for (byte[] aid : aids) {
                    ret = extractPublicData(aid, extractApplicationLabel(data));
                    if (ret == true) {
                        break;
                    }
                }
                if (!ret) {
                    card.setNfcLocked(true);
                }
            }
        } else if (LOGGER.isDebugEnabled()) {
            LOGGER.debug((contactLess ? "PPSE" : "PSE") + " not found -> Use kown AID");
        }

        return ret;
    }

    /**
     * Method used to get the aid list, if the Kernel Identifier is defined, <br/>
     * this value need to be appended to the ADF Name in the data field of <br/>
     * the SELECT command.
     *
	 * @param pData
	 *            FCI proprietary template data
     * @return the Aid to select
     */
    protected List<byte[]> getAids(final byte[] pData) {
        List<byte[]> ret = new ArrayList<byte[]>();
        List<TLV> listTlv = TlvUtil.getlistTLV(pData, EmvTags.AID_CARD, EmvTags.KERNEL_IDENTIFIER);
        for (TLV tlv : listTlv) {
            if (tlv.getTag() == EmvTags.KERNEL_IDENTIFIER && ret.size() != 0) {
                ret.add(ArrayUtils.addAll(ret.get(ret.size() - 1), tlv.getValueBytes()));
            } else {
                ret.add(tlv.getValueBytes());
            }
        }
        return ret;
    }

    /**
     * Read EMV card with AID
     */
    protected void readWithAID() throws CommunicationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Try to read card with AID");
        }
        // Test each card from know EMV AID
        for (EmvCardScheme type : EmvCardScheme.values()) {
            for (byte[] aid : type.getAidByte()) {
                if (extractPublicData(aid, type.getName())) {
                    return;
                }
            }
        }
    }

    /**
     * Select application with AID or RID
     *
	 * @param pAid
	 *            byte array containing AID or RID
     * @return response byte array
     * @throws CommunicationException
     */
    protected byte[] selectAID(final byte[] pAid) throws CommunicationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Select AID: " + BytesUtils.bytesToString(pAid));
        }
        return provider.transceive(new CommandApdu(CommandEnum.SELECT, pAid, 0).toBytes());
    }

    /**
     * Read public card data from parameter AID
     *
	 * @param pAid
	 *            card AID in bytes
	 * @param pApplicationLabel
	 *            application scheme (Application label)
     * @return true if succeed false otherwise
     */
    protected boolean extractPublicData(final byte[] pAid, final String pApplicationLabel) throws CommunicationException {
        boolean ret = false;
        // Select AID
        byte[] data = selectAID(pAid);
        // check response
        if (ResponseUtils.isSucceed(data)) {
            // Parse select response
            ret = parse(data, provider);
            if (ret) {
                // Get AID
                String aid = BytesUtils.bytesToStringNoSpace(TlvUtil.getValue(data, EmvTags.DEDICATED_FILE_NAME));
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Application label:" + pApplicationLabel + " with Aid:" + aid);
                }
                card.setAid(aid);
                card.setType(findCardScheme(aid, card.getCardNumber()));
                card.setApplicationLabel(pApplicationLabel);
                card.setLeftPinTry(getLeftPinTry());
            }
        }
        return ret;
    }

    /**
     * Method used to find the real card scheme
     *
	 * @param pAid
	 *            card complete AID
	 * @param pCardNumber
	 *            card number
     * @return card scheme
     */
    protected EmvCardScheme findCardScheme(final String pAid, final String pCardNumber) {
        EmvCardScheme type = EmvCardScheme.getCardTypeByAid(pAid);
        // Get real type for french card
        if (type == EmvCardScheme.CB) {
            type = EmvCardScheme.getCardTypeByCardNumber(pCardNumber);
            if (type != null) {
                LOGGER.debug("Real type:" + type.getName());
            }
        }
        return type;
    }

    /**
     * Method used to extract Log Entry from Select response
     *
	 * @param pSelectResponse
	 *            select response
     * @return byte array
     */
    protected byte[] getLogEntry(final byte[] pSelectResponse) {
        return TlvUtil.getValue(pSelectResponse, EmvTags.LOG_ENTRY, EmvTags.VISA_LOG_ENTRY);
    }

    /**
     * Method used to parse EMV card
     */
    protected boolean parse(final byte[] pSelectResponse, final IProvider pProvider) throws CommunicationException {
        boolean ret = false;
        // Get TLV log entry
        byte[] logEntry = getLogEntry(pSelectResponse);
        // Get PDOL
        byte[] pdol = TlvUtil.getValue(pSelectResponse, EmvTags.PDOL);
        // Send GPO Command
        byte[] gpo = getGetProcessingOptions(pdol, pProvider);

        // Check empty PDOL
        if (!ResponseUtils.isSucceed(gpo)) {
            gpo = getGetProcessingOptions(null, pProvider);
            // Check response
            if (!ResponseUtils.isSucceed(gpo)) {
                return false;
            }
        }

        // Extract commons card data (number, expire date, ...)
        if (extractCommonsCardData(gpo)) {

            // Extract log entry
            card.setListTransactions(extractLogEntry(logEntry));
            ret = true;
        }

        return ret;
    }

    /**
     * Method used to extract commons card data
     *
	 * @param pGpo
	 *            global processing options response
     */
    protected boolean extractCommonsCardData(final byte[] pGpo) throws CommunicationException {
        boolean ret = false;
        // Extract data from Message Template 1
        byte data[] = TlvUtil.getValue(pGpo, EmvTags.RESPONSE_MESSAGE_TEMPLATE_1);
        if (data != null) {
            data = ArrayUtils.subarray(data, 2, data.length);
        } else { // Extract AFL data from Message template 2
            ret = TrackUtils.extractTrack2Data(card, pGpo);
            if (!ret) {
                data = TlvUtil.getValue(pGpo, EmvTags.APPLICATION_FILE_LOCATOR);
            } else {
                extractCardHolderName(pGpo);
            }
        }
        List<Afl> listAfl;
        if (data == null) {
            // if we are not able to parse an AFL list, just create a manual one
            // in 99% of the cards all the interesting infos are in the first few SFIs.
            listAfl = createManualAfl();
        } else {
            // Extract Afl
            listAfl = extractAfl(data);
        }
        // for each AFL
        for (Afl afl : listAfl) {
            // check all records
            for (int index = afl.getFirstRecord(); index <= afl.getLastRecord(); index++) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Parsing records: sfi: " + afl.getSfi() + ", index: " + index);
                }
                byte[] info = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, index, afl.getSfi() << 3 | 4, 0).toBytes());
                if (ResponseUtils.isEquals(info, SwEnum.SW_6C)) {
                    info = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, index, afl.getSfi() << 3 | 4,
                            info[info.length - 1]).toBytes());
                }

                // Extract card data
                if (ResponseUtils.isSucceed(info)) {
                    extractCardHolderName(info);
                    extractCaPublicKeyIndex(info);
                    extractIssuerPublicKeyTags(info);
                    extractIccPublicKeyTags(info);
                    extractIccPinEnciphermentPublicKeyTags(info);
                    TrackUtils.extractTrack2Data(card, info);
                    // if we were here, we were able to read at least one record
                    // and therefore will assume that we had found a EMV application.
                    // Returning true prevents that we will continue to look for other EMV applications.
                    if (!ret) {
                        ret = true;
                    }
                    // and we do not exit the method here, as we want to read all SFIs and records
                    // in this EMV application
                }
            }
        }
        return ret;
    }

    /**
     * If for some reason we don't get any AFL from card, construct a dummy AFL which hardcoded contains
     * the first few SLFs and records.
     *
     * @return
     */
    private List<Afl> createManualAfl() {
        List<Afl> aflList = new LinkedList<>();
        for (int i = 1; i <= 7; i++) {
            Afl afl = new Afl();
            afl.setSfi(i);
            afl.setFirstRecord(1);
            afl.setLastRecord(5);
            aflList.add(afl);
        }
        return aflList;
    }

    /**
     * Method used to get log format
     *
     * @return list of tag and length for the log format
     * @throws CommunicationException
     */
    protected List<TagAndLength> getLogFormat() throws CommunicationException {
        List<TagAndLength> ret = new ArrayList<TagAndLength>();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("GET log format");
        }
        // Get log format
        byte[] data = provider.transceive(new CommandApdu(CommandEnum.GET_DATA, 0x9F, 0x4F, 0).toBytes());
        if (ResponseUtils.isSucceed(data)) {
            ret = TlvUtil.parseTagAndLength(TlvUtil.getValue(data, EmvTags.LOG_FORMAT));
        }
        return ret;
    }

    /**
     * Method used to extract log entry from card
     *
	 * @param pLogEntry
	 *            log entry position
     */
    protected List<EmvTransactionRecord> extractLogEntry(final byte[] pLogEntry) throws CommunicationException {
        List<EmvTransactionRecord> listRecord = new ArrayList<EmvTransactionRecord>();
        // If log entry is defined
        if (pLogEntry != null) {
            List<TagAndLength> tals = getLogFormat();
            // read all records
            for (int rec = 1; rec <= pLogEntry[1]; rec++) {
                byte[] response = provider.transceive(new CommandApdu(CommandEnum.READ_RECORD, rec, pLogEntry[0] << 3 | 4, 0).toBytes());
                // Extract data
                if (ResponseUtils.isSucceed(response)) {
                    EmvTransactionRecord record = new EmvTransactionRecord();
                    record.parse(response, tals);

                    // Fix artifact in EMV VISA card
                    if (record.getAmount() >= 1500000000) {
                        record.setAmount(record.getAmount() - 1500000000);
                    }

                    // Skip transaction with nul amount
                    if (record.getAmount() == null || record.getAmount() == 0) {
                        continue;
                    }

                    if (record != null) {
                        // Unknown currency
                        if (record.getCurrency() == null) {
                            record.setCurrency(CurrencyEnum.XXX);
                        }
                        listRecord.add(record);
                    }
                } else {
                    // No more transaction log or transaction disabled
                    break;
                }
            }
        }
        return listRecord;
    }

    /**
     * Extract list of application file locator from Afl response
     *
	 * @param pAfl
	 *            AFL data
     * @return list of AFL
     */
    protected List<Afl> extractAfl(final byte[] pAfl) {
        List<Afl> list = new ArrayList<Afl>();
        ByteArrayInputStream bai = new ByteArrayInputStream(pAfl);
        while (bai.available() >= 4) {
            Afl afl = new Afl();
            afl.setSfi(bai.read() >> 3);
            afl.setFirstRecord(bai.read());
            afl.setLastRecord(bai.read());
            afl.setOfflineAuthentication(bai.read() == 1);
            list.add(afl);
        }
        return list;
    }

    /**
     * Extract card holder lastname and firstname
     *
	 * @param pData
	 *            card data
     */
    protected void extractCardHolderName(final byte[] pData) {
        // Extract Card Holder name (if exist)
        byte[] cardHolderByte = TlvUtil.getValue(pData, EmvTags.CARDHOLDER_NAME);
        if (cardHolderByte != null) {
            String[] name = StringUtils.split(new String(cardHolderByte).trim(), CARD_HOLDER_NAME_SEPARATOR);
            if (name != null && name.length == 2) {
                card.setHolderFirstname(StringUtils.trimToNull(name[0]));
                card.setHolderLastname(StringUtils.trimToNull(name[1]));
            }
        }
    }

    /**
     * Extract CA public key index
     *
     * @param pData card data
     * @author Johannes Zweng
     */
    protected void extractCaPublicKeyIndex(final byte[] pData) {
        final byte[] caPubliceKeyIndex = TlvUtil.getValue(pData, EmvTags.CA_PUBLIC_KEY_INDEX_CARD);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("extracting ca pubkey index..");
        }
        if (caPubliceKeyIndex != null) {
            BitUtils bitreader = new BitUtils(caPubliceKeyIndex);
            // Tag 8f (CA_PUBLIC_KEY_INDEX_CARD) should have 1 byte (8 bit)
            card.setCaPublicKeyIndex(bitreader.getNextInteger(8));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("found ca pubkey index: " + card.getCaPublicKeyIndex());
            }
        }
    }


    /**
     * Extract all tags related to and needed for recovering of the issuer's (bank which issued the card)
     * public RSA key (as the public key is not stored in cleartext on the card).
     *
     * @param pData card data
     * @author Johannes Zweng
     */
    protected void extractIssuerPublicKeyTags(final byte[] pData) {
        final byte[] issuerPubKeyCert = TlvUtil.getValue(pData, EmvTags.ISSUER_PUBLIC_KEY_CERT);
        if (issuerPubKeyCert != null && issuerPubKeyCert.length > 0) {
            card.setIssuerPublicKeyCertificate(issuerPubKeyCert);
        }
        final byte[] issuerPubKeyRemainder = TlvUtil.getValue(pData, EmvTags.ISSUER_PUBLIC_KEY_REMAINDER);
        if (issuerPubKeyRemainder != null && issuerPubKeyRemainder.length > 0) {
            card.setIssuerPublicKeyRemainder(issuerPubKeyRemainder);
        }
        final byte[] issuerPubKeyExponent = TlvUtil.getValue(pData, EmvTags.ISSUER_PUBLIC_KEY_EXP);
        if (issuerPubKeyExponent != null && issuerPubKeyExponent.length > 0) {
            card.setIssuerPublicKeyExponent(issuerPubKeyExponent);
        }
    }


    /**
     * Extract all tags related to and needed for recovering of the ICC's (the card's)
     * public RSA key (as the public key is not stored in cleartext on the card). Only cards
     * which support DDA or CDA must include an ICC RSA key, so this might not be present on
     * all cards.
     *
     * @param pData card data
     * @author Johannes Zweng
     */
    protected void extractIccPublicKeyTags(final byte[] pData) {
        final byte[] iccPubKeyCert = TlvUtil.getValue(pData, EmvTags.ICC_PUBLIC_KEY_CERT);
        if (iccPubKeyCert != null && iccPubKeyCert.length > 0) {
            card.setIccPublicKeyCertificate(iccPubKeyCert);
        }
        final byte[] iccPubKeyRemainder = TlvUtil.getValue(pData, EmvTags.ICC_PUBLIC_KEY_REMAINDER);
        if (iccPubKeyRemainder != null && iccPubKeyRemainder.length > 0) {
            card.setIccPublicKeyRemainder(iccPubKeyRemainder);
        }
        final byte[] iccPubKeyExponent = TlvUtil.getValue(pData, EmvTags.ICC_PUBLIC_KEY_EXP);
        if (iccPubKeyExponent != null && iccPubKeyExponent.length > 0) {
            card.setIccPublicKeyExponent(iccPubKeyExponent);
        }
    }


    /**
     * Extract all tags related to and needed for recovering of the public RSA key
     * used for PIN encipherment (might not be present on all cards).
     *
     * @param pData card data
     * @author Johannes Zweng
     */
    protected void extractIccPinEnciphermentPublicKeyTags(final byte[] pData) {
        final byte[] iccPinEncPubKeyCert = TlvUtil.getValue(pData, EmvTags.ICC_PIN_ENCIPHERMENT_PUBLIC_KEY_CERT);
        if (iccPinEncPubKeyCert != null && iccPinEncPubKeyCert.length > 0) {
            card.setIccPinEnciphermentPublicKeyCertificate(iccPinEncPubKeyCert);
        }
        final byte[] iccPinEncPubKeyRemainder = TlvUtil.getValue(pData, EmvTags.ICC_PIN_ENCIPHERMENT_PUBLIC_KEY_REM);
        if (iccPinEncPubKeyRemainder != null && iccPinEncPubKeyRemainder.length > 0) {
            card.setIccPinEnciphermentPublicKeyRemainder(iccPinEncPubKeyRemainder);
        }
        final byte[] iccPinEncPubKeyExponent = TlvUtil.getValue(pData, EmvTags.ICC_PIN_ENCIPHERMENT_PUBLIC_KEY_EXP);
        if (iccPinEncPubKeyExponent != null && iccPinEncPubKeyExponent.length > 0) {
            card.setIccPinEnciphermentPublicKeyExponent(iccPinEncPubKeyExponent);
        }
    }


    /**
     * Method used to create GPO command and execute it
     *
	 * @param pPdol
	 *            PDOL data
	 * @param pProvider
	 *            provider
     * @return return data
     */
    protected byte[] getGetProcessingOptions(final byte[] pPdol, final IProvider pProvider) throws CommunicationException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending GPO with PDOL: " + BytesUtils.bytesToString(pPdol));
        }
        // List Tag and length from PDOL
        List<TagAndLength> list = TlvUtil.parseTagAndLength(pPdol);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(EmvTags.COMMAND_TEMPLATE.getTagBytes()); // COMMAND
            // TEMPLATE
            out.write(TlvUtil.getLength(list)); // ADD total length
            if (list != null) {
                for (TagAndLength tl : list) {
                    out.write(EmvTerminal.constructValue(tl));
                }
            }
        } catch (IOException ioe) {
            LOGGER.error("Construct GPO Command:" + ioe.getMessage(), ioe);
        }
        return pProvider.transceive(new CommandApdu(CommandEnum.GPO, out.toByteArray(), 0).toBytes());
    }

    /**
     * Method used to get the field card
     *
     * @return the card
     */
    public EmvCard getCard() {
        return card;
    }

}
