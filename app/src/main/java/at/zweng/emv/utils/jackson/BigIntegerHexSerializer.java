package at.zweng.emv.utils.jackson;

import at.zweng.emv.utils.EmvParsingException;
import at.zweng.emv.utils.EmvUtils;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import fr.devnied.bitlib.BytesUtils;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author Johannes Zweng on 24.10.17.
 */
public class BigIntegerHexSerializer extends StdSerializer<BigInteger> {

    public BigIntegerHexSerializer() {
        super(BigInteger.class);
    }

    @Override
    public void serialize(BigInteger value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        try {
            gen.writeString(BytesUtils.bytesToStringNoSpace(EmvUtils.getUnsignedBytes(value)));
        } catch (EmvParsingException e) {
            throw new IOException("parsing error", e);
        }
    }
}
