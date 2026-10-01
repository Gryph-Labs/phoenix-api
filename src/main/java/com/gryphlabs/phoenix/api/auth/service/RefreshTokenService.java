package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.RefreshToken;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository repository;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public IssuedRefreshToken issue(User user, Duration lifetime) {
        return issue(user, lifetime, false);
    }

    public IssuedRefreshToken issue(User user, Duration lifetime, boolean rememberMe) {
        return issue(user, lifetime, rememberMe, UUID.randomUUID());
    }

    public IssuedRefreshToken issue(User user, Duration lifetime, boolean rememberMe, UUID familyId) {
        var raw = new byte[32];
        random.nextBytes(raw);
        var token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        var entity = new RefreshToken();
        entity.setTokenHash(hash(token));
        entity.setUser(user);
        entity.setFamilyId(familyId);
        entity.setCreatedAt(clock.instant());
        entity.setExpiresAt(clock.instant().plus(lifetime));
        entity.setRememberMe(rememberMe);
        repository.save(entity);
        return new IssuedRefreshToken(token, entity);
    }

    public java.util.Optional<RefreshToken> findForUpdate(String rawToken) {
        return repository.findByTokenHash(hash(rawToken));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(java.util.UUID familyId) {
        repository.revokeFamily(familyId);
    }

    @Transactional
    public void revokeFamilyInCurrentTransaction(java.util.UUID familyId) {
        repository.revokeFamily(familyId);
    }

    public void revoke(@NonNull RefreshToken token) {
        token.setRevoked(true);
        repository.save(token);
    }

    public void revokeUser(Long userId) {
        repository.revokeUser(userId);
    }

    public static String hash(@NonNull String rawToken) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    public record IssuedRefreshToken(String rawToken, RefreshToken entity) {
    }
}
