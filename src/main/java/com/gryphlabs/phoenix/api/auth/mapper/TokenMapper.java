package com.gryphlabs.phoenix.api.auth.mapper;

import com.gryphlabs.phoenix.api.auth.service.RefreshTokenService;
import com.gryphlabs.phoenix.api.generated.auth.model.AccessTokenResponse;
import com.gryphlabs.phoenix.api.generated.auth.model.TokenResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class TokenMapper {
    @NonNull
    public TokenResponse toTokenResponse(
            @NonNull String accessToken,
            RefreshTokenService.IssuedRefreshToken refreshToken,
            @NonNull Duration accessLifetime,
            @NonNull Duration refreshLifetime) {
        return new TokenResponse(
                accessToken,
                refreshToken.rawToken(),
                "Bearer",
                accessLifetime.toSeconds(),
                refreshLifetime.toSeconds());
    }

    @NonNull
    public AccessTokenResponse toAccessTokenResponse(@NonNull String accessToken, @NonNull Duration accessLifetime) {
        return new AccessTokenResponse(accessToken, "Bearer", accessLifetime.toSeconds());
    }
}
