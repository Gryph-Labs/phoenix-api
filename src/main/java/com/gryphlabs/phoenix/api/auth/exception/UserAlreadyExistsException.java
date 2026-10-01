package com.gryphlabs.phoenix.api.auth.exception;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException() {
        super("User already exists.");
    }
}
