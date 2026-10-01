package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.dto.Credentials;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {
    @Mock
    private PasswordValidator passwordValidator;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private CredentialService credentialService;

    @Test
    void validatesNormalizesAndEncodesCredentials() {
        when(passwordEncoder.encode("Plain1")).thenReturn("encoded-password");

        Credentials credentials = credentialService.process(" Person@Example.COM ", "Plain1");

        verify(passwordValidator).validate("Plain1");
        verify(passwordEncoder).encode("Plain1");
        assertEquals("person@example.com", credentials.email());
        assertEquals("encoded-password", credentials.password());
    }
}
