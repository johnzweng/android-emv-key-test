package at.zweng.emv.utils.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import fr.devnied.bitlib.BytesUtils;

import java.io.IOException;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class ByteArrayHexDeserializer extends StdDeserializer<byte[]> {

    public ByteArrayHexDeserializer() {
        super(byte[].class);
    }

    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        JsonNode node = p.getCodec().readTree(p);
        return BytesUtils.fromString(node.asText());
    }
}
