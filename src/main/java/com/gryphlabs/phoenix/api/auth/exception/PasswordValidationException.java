package com.gryphlabs.phoenix.api.auth.exception;

import lombok.Getter;

import java.util.List;

public class PasswordValidationException extends RuntimeException {
    @Getter
    private final List<String> errors;

    public PasswordValidationException(List<String> errors) {
        super("Password validation failed.");
        this.errors = errors;
    }
}
