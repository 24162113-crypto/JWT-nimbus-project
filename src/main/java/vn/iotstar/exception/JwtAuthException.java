package vn.iotstar.exception;

public class JwtAuthException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public JwtAuthException(String message) { super(message); }
}
