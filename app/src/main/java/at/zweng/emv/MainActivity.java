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

//import sasc.emv.CA;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getName();
    private NFCUtils mNfcUtils;
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
        mNfcUtils = new NFCUtils(this);
        statusText = findViewById(R.id.statusText);
        scrollView = findViewById(R.id.scrollView);
        // init known Root CA's from XML file in resources
    }

    @Override
    protected void onResume() {
        mNfcUtils.enableDispatch();
        super.onResume();
    }

    @Override
    protected void onPause() {
        super.onPause();
        mNfcUtils.disableDispatch();
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
                    log("Start reading card.... Please wait....");
                    // TODO: clear, show spinner or something similiar
                }

                @Override
                protected void doInBackground() {
                    mTagcomm = IsoDep.get(mTag);
                    if (mTagcomm == null) {
                        // TODO: show error toast or snackbar
                        log("we have no card, will exit :-(");
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
                                debugKeys();
                            } else {
                                // TODO: handle unknown
                                Log.w(TAG, "reading finished, no exception but cardNumber is null or empty..");
                                log("Sorry, I didn't get that (got no cardnumber). Please try again.");
                            }
                        } else {
                            Log.w(TAG, "reading finished, no exception but card == null..");
                            log("Sorry, I couldn parse data. Try again (card is null).");
                        }
                    } else {
                        // TODO handle mException
                        Log.w(TAG, "reading finished with exception..");
                        log("Sorry, we catched an exception. Please try again.");
                    }
                }
            }.execute();
        }
    }

    private void debugKeys() {
        //        log("=====================================");
        //        log("=====================================");
        //        log("reading finished, and we got a card. :) Card number: " +
        //                mReadCard.getCardNumber());
        //        log("Issuer pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyCertificate()));
        //        log("Issuer pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyRemainder()));
        //        log("Issuer pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyExponent()));
        //        log("ICC pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyCertificate()));
        //        log("ICC pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyRemainder()));
        //        log("ICC pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyExponent()));
        //        log("PIN pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyCertificate()));
        //        log("PIN pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyRemainder()));
        //        log("PIN pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyExponent()));
        //        log("=====================================");


        try {
            RootCaManager rootCaManager = new RootCaManager(this);
            // RID is first 5 bytes of AID
            final RootCa rootCaForCardScheme = rootCaManager.getCaForRid(mReadCard.getAid().substring(0, 10));
            final CaPublicKey caKey = rootCaForCardScheme.getCaPublicKeyWithIndex(mReadCard.getCaPublicKeyIndex());
            EmvKeyReader keyReader = new EmvKeyReader();

            final EmvPublicKey issuerKey = keyReader.parseIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                    mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent());
            log("-----------------------------");
            log("CA key size: " + (caKey.getModulusBytes().length * 8) + " bits");
            log("CA key Modulus:\n" + BytesUtils.bytesToString(caKey.getModulusBytes()));
            log("CA key Exponent: " + BytesUtils.bytesToString(caKey.getPublicExponentBytes()));
            log("CA key expiration date: " + formatDate(caKey.getExpirationDate()));
            log("CA key ROCA vulnerable: " + ROCACheck.isAffectedByROCA(caKey.getModulus()));
            log("-----------------------------");
            log("Issuer pubkey size: " + (issuerKey.getModulusBytes().length * 8) + " bits");
            log("Issuer pubkey Modulus:\n" + BytesUtils.bytesToString(issuerKey.getModulusBytes()));
            log("Issuer pubkey Exponent: " + BytesUtils.bytesToString(issuerKey.getPublicExponentBytes()));
            log("Issuer pubkey expiration date: " + formatDate(issuerKey.getExpirationDate()));
            log("Issuer pubkey is valid: " + keyReader.validateIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                    mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent()));
            log("Issuer pubkey ROCA vulnerable: " + ROCACheck.isAffectedByROCA(issuerKey.getModulus()));
            log("-----------------------------");
        } catch (Exception e) {
            Log.e(TAG, "Exception catched while key validation.", e);
            log("Exception catched while key validation: " + e.getClass().getCanonicalName());
            log(e.getLocalizedMessage());
            log(ExceptionUtils.getStackTrace(e));
        }
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
