package com.gryphlabs.phoenix.api.auth.mapper;

import com.gryphlabs.phoenix.api.auth.service.RefreshTokenService;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthMapperTest {
    private final TokenMapper tokenMapper = new TokenMapper();
    private final MessageMapper messageMapper = new MessageMapper();

    @Test
    void mapsRefreshAndAccessTokenResponses() {
        var refresh = new RefreshTokenService.IssuedRefreshToken("refresh", null);

        var tokenResponse = tokenMapper.toTokenResponse("access", refresh,
                Duration.ofMinutes(15), Duration.ofDays(7));
        var accessResponse = tokenMapper.toAccessTokenResponse("access", Duration.ofMinutes(15));

        assertEquals("access", tokenResponse.getAccessToken());
        assertEquals("refresh", tokenResponse.getRefreshToken());
        assertEquals(900L, tokenResponse.getExpiresIn());
        assertEquals(604800L, tokenResponse.getRefreshExpiresIn());
        assertEquals("access", accessResponse.getAccessToken());
        assertEquals(900L, accessResponse.getExpiresIn());
    }

    @Test
    void mapsMessageResponse() {
        assertEquals("message", messageMapper.of("message").getMessage());
    }
}
