package at.zweng.emv.utils;

/**
 * Parsing Exception
 *
 * @author Johannes Zweng (johannes@zweng.at) on 23.10.17.
 */
public class EmvParsingException extends Exception {
    public EmvParsingException() {
    }

    public EmvParsingException(String message) {
        super(message);
    }

    public EmvParsingException(String message, Throwable cause) {
        super(message, cause);
    }
}
