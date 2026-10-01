package com.gryphlabs.phoenix.api.auth.dto;

public record Credentials(
        String email,
        String password) {
}
