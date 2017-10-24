package at.zweng.emv.ca;

import android.content.Context;
import at.zweng.emv.R;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.devnied.bitlib.BytesUtils;
import lombok.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Manages all Root-CAs for all supported card schemes. Offers methods for
 * retrieving the Root-CA keys for a specific card-scheme.
 *
 * @author Johannes Zweng on 24.10.17.
 */
public class RootCaManager {

    public RootCaManager(Context ctx) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        InputStream rawJsonInputStream = ctx.getResources().openRawResource(R.raw.cardschemes_public_root_ca_keys);
        rootCAs = objectMapper.readValue(new InputStreamReader(rawJsonInputStream),
                new TypeReference<Map<String, RootCa>>() {
                });
    }


    /**
     * Map using RID (represented as hex string) as key and RootCAs as values.
     */
    private final Map<String, RootCa> rootCAs;

    /**
     * Get the root CA for the given RID identifier bytes
     *
     * @param rid the RID identifying a card scheme (i.e. 0xA000000003 for VISA
     *            or 0xA000000004 for MASTERCARD)
     * @return root CA containing well-known public root CA keys for the card scheme
     */
    public RootCa getCaForRid(@NonNull byte[] rid) {
        return getCaForRid(BytesUtils.bytesToStringNoSpace(rid).toUpperCase());
    }

    /**
     * Get the root CA for the given RID identifier bytes
     *
     * @param ridAsString the RID identifying a card scheme (i.e. 0xA000000003 for VISA
     *            or 0xA000000004 for MASTERCARD)
     * @return root CA containing well-known public root CA keys for the card scheme
     */
    public RootCa getCaForRid(@NonNull String ridAsString) {
        return rootCAs.get(ridAsString.toUpperCase());
    }

}
