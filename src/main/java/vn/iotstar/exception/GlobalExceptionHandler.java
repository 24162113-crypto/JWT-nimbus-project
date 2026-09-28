package vn.iotstar.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private ProblemDetail build(HttpStatus status, Exception e, String description) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, e.getMessage());
        pd.setProperty("description", description);
        return pd;
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        if (exception instanceof BadCredentialsException)
            return build(HttpStatus.UNAUTHORIZED, exception, "The username or password is incorrect");
        if (exception instanceof AccountStatusException)
            return build(HttpStatus.FORBIDDEN, exception, "The account is locked");
        if (exception instanceof AccessDeniedException)
            return build(HttpStatus.FORBIDDEN, exception, "You are not authorized to access this resource");
        if (exception instanceof ExpiredTokenException)
            return build(HttpStatus.UNAUTHORIZED, exception, "The JWT token has expired");
        if (exception instanceof JwtAuthException)
            return build(HttpStatus.UNAUTHORIZED, exception, "The JWT is invalid");
        if (exception instanceof IllegalArgumentException)
            return build(HttpStatus.BAD_REQUEST, exception, exception.getMessage());
        exception.printStackTrace();
        return build(HttpStatus.INTERNAL_SERVER_ERROR, exception, "Unknown internal server error.");
    }
}
