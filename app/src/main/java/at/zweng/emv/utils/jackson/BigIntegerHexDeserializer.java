package at.zweng.emv.utils.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import fr.devnied.bitlib.BytesUtils;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class BigIntegerHexDeserializer extends StdDeserializer<BigInteger> {

    public BigIntegerHexDeserializer() {
        super(BigInteger.class);
    }

    @Override
    public BigInteger deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        JsonNode node = p.getCodec().readTree(p);
        return new BigInteger(1, BytesUtils.fromString(node.asText()));
    }

}
