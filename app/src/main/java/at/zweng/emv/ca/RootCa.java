package at.zweng.emv.ca;

import at.zweng.emv.keys.CaPublicKey;
import lombok.Getter;
import lombok.Setter;

/**
 * Contains all public certificates for one card-system (VISA, Mastercard, etc)
 * root CA.
 *
 * @author Johannes Zweng on 24.10.17.
 */
public class RootCa {

    public RootCa() {
    }

    /**
     * Human readable name of card scheme (like "MASTERCARD" or "VISA")
     */
    @Getter
    @Setter
    private String cardSchemeName;

    @Getter
    @Setter
    private CaPublicKey[] caPublicKeys;

    /**
     * Retrieve the public CA key with the given RID index. See public lists like:
     * https://www.eftlab.co.uk/index.php/site-map/knowledge-base/243-ca-public-keys
     *
     * @param index published index of the CA key to retrieve
     * @return the CA public key or null if not found
     */
    public CaPublicKey getCaPublicKeyWithIndex(final int index) {
        for (CaPublicKey key : caPublicKeys) {
            if (key.getIndex() == index) {
                return key;
            }
        }
        return null;
    }
}
