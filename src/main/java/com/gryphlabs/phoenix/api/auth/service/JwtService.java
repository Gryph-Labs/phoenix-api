package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;

@Service
public class JwtService {
    private final SecretKey key;
    private final Duration accessLifetime;
    private final Duration serviceAccessLifetime;
    private final Clock clock;

    @Autowired
    public JwtService(@Value("${app.security.jwt.secret}") @NonNull String secret,
                      @Value("${app.security.jwt.access-token-expiration}") Duration accessLifetime,
                      @Value("${app.security.jwt.service-access-token-expiration:1h}") Duration serviceAccessLifetime,
                      Clock clock) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessLifetime = accessLifetime;
        this.serviceAccessLifetime = serviceAccessLifetime;
        this.clock = clock;
    }

    public JwtService(String secret, Duration accessLifetime, Clock clock) {
        this(secret, accessLifetime, Duration.ofHours(1), clock);
    }

    public String createAccessToken(@NonNull User user) {
        return createAccessToken(
                user.getId().toString(),
                "user",
                user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(), accessLifetime);
    }

    public String createAccessToken(@NonNull ServiceClient client) {
        return createAccessToken(client.getId().toString(), client.getOwner().getId().toString(), "service", client.getAuthorities(), serviceAccessLifetime);
    }

    private String createAccessToken(String subject, String actor, java.util.Collection<String> authorities, Duration lifetime) {
        return createAccessToken(subject, null, actor, authorities, lifetime);
    }

    private String createAccessToken(String subject, String ownerId, String actor, java.util.Collection<String> authorities, Duration lifetime) {
        var now = clock.instant();
        var builder = Jwts.builder().subject(subject).claim("actor", actor);
        if (ownerId != null) {
            builder.claim("ownerId", ownerId);
        }
        return builder
                .claim("authorities", authorities)
                .issuedAt(Date.from(now)).expiration(Date.from(now.plus(lifetime)))
                .signWith(key).compact();
    }

    public Claims parseAndValidate(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .clock(() -> Date.from(clock.instant()))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Duration accessLifetime() {
        return accessLifetime;
    }

    public Duration serviceAccessLifetime() {
        return serviceAccessLifetime;
    }
}
