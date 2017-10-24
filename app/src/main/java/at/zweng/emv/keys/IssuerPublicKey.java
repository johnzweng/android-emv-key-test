package at.zweng.emv.keys;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.math.BigInteger;
import java.util.Date;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class IssuerPublicKey extends EmvPublicKey {
    public IssuerPublicKey(BigInteger publicExponent, BigInteger modulus, byte[] emvCertificate, Date expirationDate) {
        super(publicExponent, modulus, emvCertificate, expirationDate);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM_RSA;
    }

    @Override
    public String getFormat() {
        return FORMAT_ISSUER_PUBKEY;
    }
}
