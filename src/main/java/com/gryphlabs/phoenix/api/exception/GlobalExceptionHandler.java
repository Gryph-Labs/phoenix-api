package com.gryphlabs.phoenix.api.exception;

import com.gryphlabs.phoenix.api.auth.exception.PasswordValidationException;
import com.gryphlabs.phoenix.api.generated.model.ErrorResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(PasswordValidationException.class)
    public ResponseEntity<ErrorResponse> handlePasswordValidationException(@NonNull PasswordValidationException ex) {
        var response = new ErrorResponse();
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setMessage("Validation failed.");
        response.setErrors(ex.getErrors());
        response.setTimestamp(OffsetDateTime.now(ZoneOffset.UTC));

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }
}
