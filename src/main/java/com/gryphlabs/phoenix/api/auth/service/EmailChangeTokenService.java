package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.EmailChangeToken;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.repository.EmailChangeTokenRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EmailChangeTokenService {
    private final EmailChangeTokenRepository repository;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public Issued issue(@NonNull User user, String email, Duration lifetime) {
        repository.consumeForUser(user.getId());
        byte[] b = new byte[32];
        random.nextBytes(b);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(b);

        var t = new EmailChangeToken();
        t.setTokenHash(hash(raw));
        t.setUser(user);
        t.setProposedEmail(email);
        t.setExpiresAt(clock.instant().plus(lifetime));
        repository.save(t);

        return new Issued(raw, t);
    }

    public Optional<EmailChangeToken> find(String raw) {
        return repository.findByTokenHash(hash(raw));
    }

    public void consume(@NonNull EmailChangeToken token) {
        token.setConsumed(true);
        repository.save(token);
    }

    public static String hash(String raw) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256")
                            .digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record Issued(String rawToken, EmailChangeToken entity) {
    }
}
