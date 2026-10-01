package com.gryphlabs.phoenix.api.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security.password")
public record PasswordProperties(
        int minLength,
        int uppercase,
        int lowercase,
        int numbers,
        int special,
        String specialCharacters) {
}
