package at.zweng.emv.keys;

import at.zweng.emv.utils.EmvParsingException;
import at.zweng.emv.utils.EmvUtils;
import at.zweng.emv.utils.jackson.ByteArrayHexDeserializer;
import at.zweng.emv.utils.jackson.ByteArrayHexSerializer;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Value;

import java.math.BigInteger;
import java.util.Date;

/**
 * @author Johannes Zweng on 23.10.17.
 */
@Value
@EqualsAndHashCode(callSuper = true)
public class CaPublicKey extends EmvPublicKey {

    @JsonCreator
    public CaPublicKey(@JsonProperty("index") int index,
                       @JsonProperty("publicExponent") BigInteger publicExponent,
                       @JsonProperty("modulus") BigInteger modulus,
                       @JsonProperty("expirationDate") Date expirationDate,
                       @JsonProperty("hashAlgorithmIndicator") int hashAlgorithmIndicator,
                       @JsonProperty("publicKeyAlgorithmIndicator") int publicKeyAlgorithmIndicator,
                       @JsonProperty("hash") byte[] hash) throws EmvParsingException {
        super(publicExponent, modulus, EmvUtils.getUnsignedBytes(modulus), expirationDate);
        this.index = index;
        this.hashAlgorithmIndicator = hashAlgorithmIndicator;
        this.publicKeyAlgorithmIndicator = publicKeyAlgorithmIndicator;
        this.hash = hash;
    }

    @Override
    @JsonIgnore
    public String getAlgorithm() {
        return ALGORITHM_RSA;
    }

    @Override
    @JsonIgnore
    public String getFormat() {
        return FORMAT_CA_MODULUS;
    }

    @Getter
    int index;

    @Getter
    int hashAlgorithmIndicator;

    @Getter
    int publicKeyAlgorithmIndicator;

    /**
     * Hash value is calculated by hashing the RID, the index, the modulus
     * and the exponent, using the hash algorithm indicated by hashAlgorithmIndicator.
     */
    @Getter
    @JsonSerialize(using = ByteArrayHexSerializer.class)
    @JsonDeserialize(using = ByteArrayHexDeserializer.class)
    byte[] hash;
}
