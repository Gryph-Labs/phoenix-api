package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.PasswordActionToken;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.repository.PasswordActionTokenRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordActionTokenService {
    private final PasswordActionTokenRepository repository;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public Issued issue(User user, PasswordActionToken.Purpose purpose, Duration lifetime) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        var token = new PasswordActionToken();
        token.setTokenHash(hash(raw));
        token.setUser(user);
        token.setPurpose(purpose);
        token.setExpiresAt(clock.instant().plus(lifetime));
        token.setConsumed(false);
        repository.save(token);
        return new Issued(raw, token);
    }

    public Optional<PasswordActionToken> find(String raw) {
        return repository.findByTokenHash(hash(raw));
    }

    public static String hash(@NonNull String raw) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256")
                            .digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public record Issued(String rawToken, PasswordActionToken entity) {
    }
}
