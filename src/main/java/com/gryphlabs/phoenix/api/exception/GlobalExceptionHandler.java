package com.gryphlabs.phoenix.api.exception;

import com.gryphlabs.phoenix.api.auth.exception.PasswordValidationException;
import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.auth.exception.UserAlreadyExistsException;
import com.gryphlabs.phoenix.api.auth.exception.EmailAlreadyExistsException;
import com.gryphlabs.phoenix.api.auth.exception.InvalidEmailChangeException;
import com.gryphlabs.phoenix.api.generated.model.ErrorResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.List;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExists(@NonNull EmailAlreadyExistsException ex) { return errorResponse(HttpStatus.CONFLICT, ex.getMessage(), List.of()); }
    @ExceptionHandler(InvalidEmailChangeException.class)
    public ResponseEntity<ErrorResponse> handleInvalidEmailChange(@NonNull InvalidEmailChangeException ex) { return errorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), List.of()); }
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(@NonNull BadCredentialsException ex) {
        return errorResponse(HttpStatus.UNAUTHORIZED, "Invalid credentials.", List.of());
    }
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExistsException(@NonNull UserAlreadyExistsException ex) {
        return errorResponse(HttpStatus.CONFLICT, ex.getMessage(), List.of());
    }

    @ExceptionHandler(InvalidVerificationTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidVerificationTokenException(
            @NonNull InvalidVerificationTokenException ex) {
        return errorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), List.of());
    }

    @ExceptionHandler(PasswordValidationException.class)
    public ResponseEntity<ErrorResponse> handlePasswordValidationException(@NonNull PasswordValidationException ex) {
        return errorResponse(HttpStatus.BAD_REQUEST, "Validation failed.", ex.getErrors());
    }

    private ResponseEntity<ErrorResponse> errorResponse(HttpStatus status, String message, List<String> errors) {
        var response = new ErrorResponse();
        response.setStatus(status.value());
        response.setMessage(message);
        response.setErrors(errors);
        response.setTimestamp(OffsetDateTime.now(ZoneOffset.UTC));

        return new ResponseEntity<>(response, status);
    }
}
