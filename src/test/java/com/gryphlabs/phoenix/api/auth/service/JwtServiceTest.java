package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {
    private static final String SECRET = "01234567890123456789012345678901";
    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final JwtService jwt = new JwtService(SECRET, Duration.ofMinutes(15), clock);

    @Test
    void claimsContainStableIdentityActorAndAuthorities() {
        var token = jwt.createAccessToken(user());
        var claims = jwt.parseAndValidate(token);
        assertEquals("42", claims.getSubject());
        assertEquals("user", claims.get("actor"));
        assertEquals(java.util.List.of("ROLE_USER"), claims.get("authorities", java.util.List.class));
    }

    @Test
    void expiredTamperedAndMalformedTokensAreRejected() {
        var expired = new JwtService(SECRET, Duration.ofSeconds(-1), clock).createAccessToken(user());
        assertThrows(JwtException.class, () -> jwt.parseAndValidate(expired));
        var token = jwt.createAccessToken(user());
        assertThrows(JwtException.class, () -> jwt.parseAndValidate(token.substring(0, token.length() - 1) + "x"));
        assertThrows(JwtException.class, () -> jwt.parseAndValidate("not.a.jwt"));
    }

    @Test
    void humanAndServiceLifetimesAreIndependentAndServiceHasNoRefreshToken() {
        var owner = user();
        var client = new ServiceClient();
        client.setId(7L);
        client.setOwner(owner);
        var service = new JwtService(SECRET, Duration.ofMinutes(15), Duration.ofHours(1), clock);
        var humanClaims = service.parseAndValidate(service.createAccessToken(owner));
        var serviceClaims = service.parseAndValidate(service.createAccessToken(client));
        assertEquals(900L, humanClaims.getExpiration().toInstant().getEpochSecond() - humanClaims.getIssuedAt().toInstant().getEpochSecond());
        assertEquals(3600L, serviceClaims.getExpiration().toInstant().getEpochSecond() - serviceClaims.getIssuedAt().toInstant().getEpochSecond());
        assertEquals("7", serviceClaims.getSubject());
        assertEquals("42", serviceClaims.get("ownerId"));
        assertEquals(Duration.ofHours(1), service.serviceAccessLifetime());
    }

    @Test
    void callerLifetimeCanBeConfiguredWithoutChangingHumanLifetime() {
        var owner = user();
        var client = new ServiceClient();
        client.setId(7L);
        client.setOwner(owner);
        var service = new JwtService(SECRET, Duration.ofMinutes(15), Duration.ofMinutes(20), clock);
        var human = service.parseAndValidate(service.createAccessToken(owner));
        var caller = service.parseAndValidate(service.createAccessToken(client));
        assertEquals(900L, human.getExpiration().toInstant().getEpochSecond() - human.getIssuedAt().toInstant().getEpochSecond());
        assertEquals(1200L, caller.getExpiration().toInstant().getEpochSecond() - caller.getIssuedAt().toInstant().getEpochSecond());
    }

    private User user() {
        var u = new User();
        u.setId(42L);
        u.setRole(Role.USER);
        u.setStatus(UserStatus.ACTIVE);
        return u;
    }
}
