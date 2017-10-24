package at.zweng.emv;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import at.zweng.emv.ca.RootCa;
import at.zweng.emv.ca.RootCaManager;
import at.zweng.emv.keys.CaPublicKey;
import at.zweng.emv.keys.EmvPublicKey;
import at.zweng.emv.provider.Provider;
import at.zweng.emv.utils.EmvKeyReader;
import at.zweng.emv.utils.NFCUtils;
import at.zweng.emv.utils.SimpleAsyncTask;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.parser.EmvParser;
import fr.devnied.bitlib.BytesUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

//import sasc.emv.CA;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getName();
    private NFCUtils mNfcUtils;
    private EmvCard mReadCard;

    /**
     * IsoDep provider
     */
    private Provider mProvider = new Provider();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mNfcUtils = new NFCUtils(this);
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
                    Log.i(TAG, "Start reading card....");
                    // TODO: clear, show spinner or something similiar
                }

                @Override
                protected void doInBackground() {
                    mTagcomm = IsoDep.get(mTag);
                    if (mTagcomm == null) {
                        // TODO: show error toast or snackbar
                        Log.w(TAG, "Have no card, will exit.");
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
                    Log.i(TAG, "Reading finished");
                    // TODO hide spinner, etc..
                    if (!mException) {
                        if (mCard != null) {
                            if (StringUtils.isNotBlank(mCard.getCardNumber())) {
                                mReadCard = mCard;
                                debugKeys();
                            } else {
                                // TODO: handle unknown
                                Log.w(TAG, "reading finished, no exception but cardNumber is null or empty..");
                            }
                        } else {
                            Log.w(TAG, "reading finished, no exception but card == null..");
                        }
                    } else {
                        // TODO handle mException
                        Log.w(TAG, "reading finished with exception..");
                    }
                }
            }.execute();
        }
    }

    private void debugKeys() {
        Log.i(TAG, "=====================================");
        Log.i(TAG, "=====================================");
        Log.i(TAG, "reading finished, and we got a card. :) Card number: " +
                mReadCard.getCardNumber());
        Log.i(TAG, "Issuer pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyCertificate()));
        Log.i(TAG, "Issuer pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyRemainder()));
        Log.i(TAG, "Issuer pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIssuerPublicKeyExponent()));
        Log.i(TAG, "ICC pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyCertificate()));
        Log.i(TAG, "ICC pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyRemainder()));
        Log.i(TAG, "ICC pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIccPublicKeyExponent()));
        Log.i(TAG, "PIN pubkey cert: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyCertificate()));
        Log.i(TAG, "PIN pubkey remainder: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyRemainder()));
        Log.i(TAG, "PIN pubkey exponent: " + BytesUtils.bytesToString(mReadCard.getIccPinEnciphermentPublicKeyExponent()));
        Log.i(TAG, "=====================================");
        Log.i(TAG, "=====================================");


        try {
            RootCaManager rootCaManager = new RootCaManager(this);
            // RID is first 5 bytes of AID
            final RootCa rootCaForCardScheme = rootCaManager.getCaForRid(mReadCard.getAid().substring(0, 10));
            final CaPublicKey caKey = rootCaForCardScheme.getCaPublicKeyWithIndex(mReadCard.getCaPublicKeyIndex());
            EmvKeyReader keyReader = new EmvKeyReader();

            final EmvPublicKey issuerKey = keyReader.parseIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                    mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent());
            Log.i(TAG, "-----------------------------");
            Log.i(TAG, "ca key size: " + (caKey.getModulusBytes().length * 8));
            Log.i(TAG, "ca key Modulus: " + BytesUtils.bytesToString(caKey.getModulusBytes()));
            Log.i(TAG, "ca key Exponent: " + BytesUtils.bytesToString(caKey.getPublicExponentBytes()));
            Log.i(TAG, "ca key expiration date: " + caKey.getExpirationDate());
            Log.i(TAG, "-----------------------------");
            Log.i(TAG, "issuer pubkey size in bits: " + (issuerKey.getModulusBytes().length * 8));
            Log.i(TAG, "issuer pubkey Modulus: " + BytesUtils.bytesToString(issuerKey.getModulusBytes()));
            Log.i(TAG, "issuer pubkey Exponent: " + BytesUtils.bytesToString(issuerKey.getPublicExponentBytes()));
            Log.i(TAG, "issuer pubkey expiration date: " + issuerKey.getExpirationDate());
            Log.i(TAG, "issuer pubkey is valid: " + keyReader.validateIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                    mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent()));
            Log.i(TAG, "-----------------------------");
        } catch (Exception e) {
            Log.e(TAG, "Exception catched while key validation.", e);
        }
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
