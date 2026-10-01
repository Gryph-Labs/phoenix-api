package com.gryphlabs.phoenix.api.auth.exception;

public class InvalidVerificationTokenException extends RuntimeException {
    public InvalidVerificationTokenException() {
        super("The verification token is invalid, expired, or already used.");
    }
}
