package at.zweng.emv;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import at.zweng.emv.ca.RootCa;
import at.zweng.emv.ca.RootCaManager;
import at.zweng.emv.keys.CaPublicKey;
import at.zweng.emv.keys.EmvPublicKey;
import at.zweng.emv.keys.IssuerIccPublicKey;
import at.zweng.emv.keys.checks.ROCACheck;
import at.zweng.emv.provider.Provider;
import at.zweng.emv.utils.EmvKeyReader;
import at.zweng.emv.utils.NFCUtils;
import at.zweng.emv.utils.SimpleAsyncTask;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.parser.EmvParser;
import fr.devnied.bitlib.BytesUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static at.zweng.emv.utils.EmvUtils.notEmpty;

//import sasc.emv.CA;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getName();
    private NFCUtils nfcUtils;
    private EmvCard mReadCard;

    private TextView statusText;
    private ScrollView scrollView;

    /**
     * IsoDep provider
     */
    private Provider mProvider = new Provider();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        nfcUtils = new NFCUtils(this);
        statusText = findViewById(R.id.statusText);
        scrollView = findViewById(R.id.scrollView);
        // init known Root CA's from XML file in resources
    }

    @Override
    protected void onResume() {
        if (!NFCUtils.isNfcAvailable(this)) {
            cleanConsole();
            log("Sorry, this device doesn't seem to support NFC.\nThis app will not work. :-(");
        } else if (!NFCUtils.isNfcEnabled(this)) {
            cleanConsole();
            log("NFC is disabled in system settings.\nPlease enable it and restart this app.");
        } else {
            nfcUtils.enableDispatch();
        }
        super.onResume();
    }

    @Override
    protected void onPause() {
        super.onPause();
        nfcUtils.disableDispatch();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        final Tag mTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (mTag != null) {

            new SimpleAsyncTask() {
                private IsoDep mTagcomm;
                private EmvCard mCard;
                private boolean mException;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                    cleanConsole();
                    log("Start reading card. Please wait...");
                    // TODO: clear, show spinner or something similiar
                }

                @Override
                protected void doInBackground() {
                    mTagcomm = IsoDep.get(mTag);
                    if (mTagcomm == null) {
                        // TODO: show error toast or snackbar
                        log("Couldn't connect to NFC card. Please try again.");
                        return;
                    }
                    mException = false;

                    try {
                        mReadCard = null;
                        // Open connection
                        mTagcomm.connect();
                        mProvider.setmTagCom(mTagcomm);
                        EmvParser parser = new EmvParser(mProvider, true);
                        mCard = parser.readEmvCard();
                    } catch (IOException e) {
                        mException = true;
                    } finally {
                        closeQuietly(mTagcomm);
                    }
                }

                @Override
                protected void onPostExecute(final Object result) {
                    log("Reading finished.");
                    // TODO hide spinner, etc..
                    if (!mException) {
                        if (mCard != null) {
                            if (StringUtils.isNotBlank(mCard.getCardNumber())) {
                                mReadCard = mCard;
                                printResults();
                            } else {
                                Log.w(TAG, "Reading finished, but cardNumber is null or empty..");
                                log("Sorry, couldn't get parse the card.");
                            }
                        } else {
                            Log.w(TAG, "reading finished, no exception but card == null..");
                            log("Sorry, couldn't get parse the card (card is null).");
                        }
                    } else {
                        // TODO handle mException
                        Log.w(TAG, "reading finished with exception..");
                        log("Sorry, we catched an exception. Did you remove the card?\nPlease try again.");
                    }
                }
            }.execute();
        }
    }


    /**
     * Display results on screen and in log.
     * TODO: ugly dump method, clean up, build more beautiful UI
     */
    private void printResults() {
        try {
            RootCaManager rootCaManager = new RootCaManager(this);
            // RID is first 5 bytes of AID
            final RootCa rootCaForCardScheme = rootCaManager.getCaForRid(mReadCard.getAid().substring(0, 10));
            final CaPublicKey caKey = rootCaForCardScheme.getCaPublicKeyWithIndex(mReadCard.getCaPublicKeyIndex());
            EmvKeyReader keyReader = new EmvKeyReader();

            log("");
            log("-----------------------------");
            log("-----------------------------");
            log("Card details:");
            log("Card scheme: " + rootCaForCardScheme.getCardSchemeName());
            if (mReadCard.getApplicationLabel() != null) {
                log("Application label: " + mReadCard.getApplicationLabel());
            }
            log("Primary account number (PAN): " + mReadCard.getCardNumber());
            log("-----------------------------");
            log("Root CA index: " + mReadCard.getCaPublicKeyIndex());
            log("Root CA key size: " + (caKey.getModulusBytes().length * 8) + " bits " + caKey.getAlgorithm() + " key");
            log("Root CA key Modulus:\n" + BytesUtils.bytesToString(caKey.getModulusBytes()));
            log("Root CA key Exponent: " + BytesUtils.bytesToString(caKey.getPublicExponentBytes()));
            log("Root CA key expiration date: " + formatDate(caKey.getExpirationDate()));
            log("Root CA key ROCA vulnerable: " + ROCACheck.isAffectedByROCA(caKey.getModulus()));
            log("-----------------------------");
            if (notEmpty(mReadCard.getIssuerPublicKeyCertificate()) &&
                    notEmpty(mReadCard.getIssuerPublicKeyExponent())) {
                final IssuerIccPublicKey issuerKey = keyReader.parseIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                        mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent());
                log("Issuer pubkey size: " + (issuerKey.getModulusBytes().length * 8) + " bits " + issuerKey.getAlgorithm() + " key");
                log("Issuer pubkey Modulus:\n" + BytesUtils.bytesToString(issuerKey.getModulusBytes()));
                log("Issuer pubkey Exponent: " + BytesUtils.bytesToString(issuerKey.getPublicExponentBytes()));
                log("Issuer pubkey expiration date: " + formatDate(issuerKey.getExpirationDate()));
                log("Issuer pubkey is valid: " + keyReader.validateIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                        mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent()));
                log("Issuer pubkey ROCA vulnerable: " + ROCACheck.isAffectedByROCA(issuerKey.getModulus()));
                log("-----------------------------");
                if (notEmpty(mReadCard.getIccPublicKeyCertificate()) &&
                        notEmpty(mReadCard.getIccPublicKeyExponent())) {
                    final EmvPublicKey iccKey = keyReader.parseIccPublicKey(issuerKey, mReadCard.getIccPublicKeyCertificate(),
                            mReadCard.getIccPublicKeyRemainder(), mReadCard.getIccPublicKeyExponent());
                    log("ICC pubkey size: " + (iccKey.getModulusBytes().length * 8) + " bits " + iccKey.getAlgorithm() + " key");
                    log("ICC pubkey Modulus:\n" + BytesUtils.bytesToString(iccKey.getModulusBytes()));
                    log("ICC pubkey Exponent: " + BytesUtils.bytesToString(iccKey.getPublicExponentBytes()));
                    log("ICC pubkey expiration date: " + formatDate(iccKey.getExpirationDate()));
                    log("ICC pubkey ROCA vulnerable: " + ROCACheck.isAffectedByROCA(iccKey.getModulus()));
                    log("-----------------------------");
                } else {
                    log("Found no ICC key data on card. Cannot parse ICC key.");
                }
            } else {
                log("Found no issuer key data on card. Cannot parse keys.");
            }
            log("-----------------------------");
            log("");
        } catch (Exception e) {
            Log.e(TAG, "Exception catched while key validation.", e);
            log("Exception catched while key validation:\n");
            log(e.getLocalizedMessage() + "\n\n");
            log("-----------------------------");
            log("-----------------------------");
            log("Technical details below:");
            log(ExceptionUtils.getStackTrace(e));
            log("-----------------------------");
            log("-----------------------------");
        }
    }

    private void cleanConsole() {
        statusText.setText("");
    }

    private void log(String msg) {
        Log.i(TAG, msg);
        StringBuffer buf = new StringBuffer(statusText.getText());
        buf.append(msg);
        buf.append("\n");
        statusText.setText(buf);
        // and scroll down to the end
        scrollView.post(new Runnable() {
            public void run() {
                scrollView.smoothScrollTo(0, statusText.getBottom());
            }
        });
    }

    private String formatDate(Date monthYear) {
        SimpleDateFormat sdf = new SimpleDateFormat("MMMM yyyy");
        return sdf.format(monthYear);
    }

    private void closeQuietly(IsoDep tagComm) {
        try {
            if (tagComm != null) {
                tagComm.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

}
