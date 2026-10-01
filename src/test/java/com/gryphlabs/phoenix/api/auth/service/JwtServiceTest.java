package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.*;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
    private static final String SECRET = "01234567890123456789012345678901";
    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final JwtService jwt = new JwtService(SECRET, Duration.ofMinutes(15), clock);

    @Test void claimsContainStableIdentityActorAndAuthorities() {
        var token = jwt.createAccessToken(user()); var claims = jwt.parseAndValidate(token);
        assertEquals("42", claims.getSubject()); assertEquals("user", claims.get("actor"));
        assertEquals(java.util.List.of("ROLE_USER"), claims.get("authorities", java.util.List.class));
    }
    @Test void expiredTamperedAndMalformedTokensAreRejected() {
        var expired = new JwtService(SECRET, Duration.ofSeconds(-1), clock).createAccessToken(user());
        assertThrows(JwtException.class, () -> jwt.parseAndValidate(expired));
        var token = jwt.createAccessToken(user());
        assertThrows(JwtException.class, () -> jwt.parseAndValidate(token.substring(0, token.length() - 1) + "x"));
        assertThrows(JwtException.class, () -> jwt.parseAndValidate("not.a.jwt"));
    }
    private User user() { var u = new User(); u.setId(42L); u.setRole(Role.USER); u.setStatus(UserStatus.ACTIVE); return u; }
}
