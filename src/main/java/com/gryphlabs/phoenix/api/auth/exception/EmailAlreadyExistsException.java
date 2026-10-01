package com.gryphlabs.phoenix.api.auth.exception;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException() {
        super("Email address is already in use.");
    }
}
