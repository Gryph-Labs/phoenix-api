package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.dto.Credentials;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CredentialService {
    private final PasswordValidator passwordValidator;
    private final PasswordEncoder passwordEncoder;

    public Credentials process(String email, String password) {
        passwordValidator.validate(password);
        return new Credentials(normalizeEmail(email), passwordEncoder.encode(password));
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
