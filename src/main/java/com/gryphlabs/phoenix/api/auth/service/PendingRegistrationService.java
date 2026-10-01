package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.entity.PendingRegistration;
import com.gryphlabs.phoenix.api.repository.PendingRegistrationRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class PendingRegistrationService {
    private static final int TOKEN_BYTES = 32;

    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.security.registration.verification-token-expiration:24h}")
    private Duration tokenExpiration;

    @Transactional
    public IssuedSetupToken issue(String email, String displayName) {
        var pendingRegistration = pendingRegistrationRepository.findByEmail(email)
                .orElseGet(PendingRegistration::new);
        pendingRegistration.setEmail(email);
        pendingRegistration.setDisplayName(displayName);

        var rawTokenBytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(rawTokenBytes);

        var rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(rawTokenBytes);
        pendingRegistration.setTokenHash(hash(rawToken));
        pendingRegistration.setExpiresAt(Instant.now(clock).plus(tokenExpiration));
        pendingRegistrationRepository.save(pendingRegistration);

        return new IssuedSetupToken(rawToken, pendingRegistration);
    }

    @Transactional
    public PendingRegistration findValid(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidVerificationTokenException();
        }

        var pendingRegistration = pendingRegistrationRepository
                .findByTokenHash(hash(rawToken))
                .orElseThrow(InvalidVerificationTokenException::new);
        if (!pendingRegistration.getExpiresAt().isAfter(Instant.now(clock))) {
            throw new InvalidVerificationTokenException();
        }

        return pendingRegistration;
    }

    @Transactional
    public void consume(PendingRegistration pendingRegistration) {
        pendingRegistrationRepository.delete(pendingRegistration);
    }

    public String hashForStorage(String rawToken) {
        return hash(rawToken);
    }

    private String hash(@NonNull String rawToken) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of()
                    .formatHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available.", ex);
        }
    }

    public record IssuedSetupToken(String rawToken, PendingRegistration pendingRegistration) {
    }
}
