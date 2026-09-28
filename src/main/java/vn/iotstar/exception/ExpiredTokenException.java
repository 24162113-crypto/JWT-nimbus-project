package vn.iotstar.exception;

public class ExpiredTokenException extends JwtAuthException {
    private static final long serialVersionUID = 1L;
    public ExpiredTokenException(String message) { super(message); }
}
