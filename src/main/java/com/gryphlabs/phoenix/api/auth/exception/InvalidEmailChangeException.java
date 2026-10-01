package com.gryphlabs.phoenix.api.auth.exception;

public class InvalidEmailChangeException extends RuntimeException {
    public InvalidEmailChangeException() {
        super("Invalid email change request.");
    }
}
