package com.gryphlabs.phoenix.api.auth;

import com.gryphlabs.phoenix.api.auth.exception.PasswordValidationException;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.config.PasswordProperties;
import com.gryphlabs.phoenix.api.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordValidationTest {
    private final PasswordValidator validator = new PasswordValidator(
            new PasswordProperties(8, 1, 1, 1, 0, "!@#$%^&*()_+-=[]{}"));

    @Test
    void validatorUsesAuthValidationException() {
        var exception = assertThrows(PasswordValidationException.class, () -> validator.validate("weak"));
        assertEquals("Password validation failed.", exception.getMessage());
    }

    @Test
    void authValidationExceptionMapsToBadRequest() {
        var response = new GlobalExceptionHandler()
                .handlePasswordValidationException(new PasswordValidationException("Password is weak."));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Validation failed.", response.getBody().getMessage());
    }
}
