package at.zweng.emvroca;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import at.zweng.emvroca.provider.Provider;
import at.zweng.emvroca.utils.NFCUtils;
import at.zweng.emvroca.utils.SimpleAsyncTask;
import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.parser.EmvParser;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

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
                            } else {
                                // TODO: handle unknown
                                Log.w(TAG, "reading finished, no exception but cardNumber is null or empty..");
                            }
                        } else {
                            Log.w(TAG, "reading finished, no exception but card == null..");
                        }
                    }
                    else {
                        // TODO handle mException
                        Log.w(TAG, "reading finished with exception..");
                    }
                }
            }.execute();
        }
    }

    /**
     * Get ATS from isoDep
     *
     * @param pIso isodep
     * @return ATS byte array
     */
    private byte[] getAts(final IsoDep pIso) {
        byte[] ret = null;
        if (pIso.isConnected()) {
            // Extract ATS from NFC-A
            ret = pIso.getHistoricalBytes();
            if (ret == null) {
                // Extract ATS from NFC-B
                ret = pIso.getHiLayerResponse();
            }
        }
        return ret;
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
