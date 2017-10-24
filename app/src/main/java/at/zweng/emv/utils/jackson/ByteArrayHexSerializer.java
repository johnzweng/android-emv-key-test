package at.zweng.emv.utils.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import fr.devnied.bitlib.BytesUtils;

import java.io.IOException;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class ByteArrayHexSerializer extends StdSerializer<byte[]> {

    public ByteArrayHexSerializer() {
        super(byte[].class);
    }

    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeString(BytesUtils.bytesToStringNoSpace(value));
    }
}
