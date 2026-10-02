package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.mapper.TokenMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.RefreshToken;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.LogoutRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceRefreshTest {
    @Spy
    TokenMapper tokenMapper = new TokenMapper();
    @Spy
    MessageMapper messageMapper = new MessageMapper();
    @Mock
    CredentialService credentials;
    @Mock
    UserRepository users;
    @Mock
    PendingRegistrationService pending;
    @Mock
    EmailDeliveryService mail;
    @Mock
    PasswordValidator validator;
    @Mock
    PasswordEncoder encoder;
    @Mock
    JwtService jwt;
    @Mock
    RefreshTokenService tokens;
    @InjectMocks
    AuthenticationService service;
    private final User user = user();
    private final UUID family = UUID.randomUUID();

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(service, "refreshTokenExpiration", Duration.ofDays(7));
        ReflectionTestUtils.setField(service, "rememberMeRefreshTokenExpiration", Duration.ofDays(30));
        lenient().when(jwt.createAccessToken(user)).thenReturn("new-access");
        lenient().when(jwt.accessLifetime()).thenReturn(Duration.ofMinutes(15));
    }

    @Test
    void validRefreshRotatesWithinFamilyAndPreservesRememberMe() {
        var old = token("old-hash", false, Instant.now().plusSeconds(3600));
        var replacement = token("new-hash", true, Instant.now().plusSeconds(3600));
        when(tokens.findForUpdate("old")).thenReturn(Optional.of(old));
        when(tokens.issue(user, Duration.ofDays(7), false, family))
                .thenReturn(new RefreshTokenService.IssuedRefreshToken("new", replacement));
        var response = service.refresh(new RefreshRequest("old"));
        assertEquals("new-access", response.getAccessToken());
        assertEquals("new", response.getRefreshToken());
        assertEquals(900L, response.getExpiresIn());
        assertEquals(604800L, response.getRefreshExpiresIn());
        verify(tokens).revoke(old);
        assertEquals(family, replacement.getFamilyId());
        verify(tokens).issue(user, Duration.ofDays(7), false, family);
    }

    @Test
    void rememberMeLifetimeSurvivesRotation() {
        var old = token("old", true, Instant.now().plusSeconds(3600));
        when(tokens.findForUpdate("old")).thenReturn(Optional.of(old));
        when(tokens.issue(user, Duration.ofDays(30), true, family)).thenReturn(new RefreshTokenService.IssuedRefreshToken("new", token("new", true, Instant.now().plusSeconds(1))));
        assertEquals(2592000L, service.refresh(new RefreshRequest("old")).getRefreshExpiresIn());
    }

    @Test
    void revokedReplayRevokesFamilyAndUnknownExpiredDisabledFailGenerically() {
        var revoked = token("old", false, Instant.now().plusSeconds(1));
        revoked.setRevoked(true);
        when(tokens.findForUpdate("old")).thenReturn(Optional.of(revoked));
        assertThrows(BadCredentialsException.class, () -> service.refresh(new RefreshRequest("old")));
        verify(tokens).revokeFamily(family);
        when(tokens.findForUpdate("missing")).thenReturn(Optional.empty());
        assertThrows(BadCredentialsException.class, () -> service.refresh(new RefreshRequest("missing")));
        var expired = token("expired", false, Instant.now().minusSeconds(1));
        when(tokens.findForUpdate("expired")).thenReturn(Optional.of(expired));
        assertThrows(BadCredentialsException.class, () -> service.refresh(new RefreshRequest("expired")));
        user.setStatus(UserStatus.DISABLED);
        var disabled = token("disabled", false, Instant.now().plusSeconds(1));
        when(tokens.findForUpdate("disabled")).thenReturn(Optional.of(disabled));
        assertThrows(BadCredentialsException.class, () -> service.refresh(new RefreshRequest("disabled")));
    }

    @Test
    void logoutRevokesFamilyAndRepeatedUnknownLogoutIsSafe() {
        var token = token("old", false, Instant.now().plusSeconds(1));
        when(tokens.findForUpdate("old")).thenReturn(Optional.of(token));
        service.logout(new LogoutRequest("old"));
        verify(tokens).revokeFamilyInCurrentTransaction(family);
        when(tokens.findForUpdate("missing")).thenReturn(Optional.empty());
        assertDoesNotThrow(() -> service.logout(new LogoutRequest("missing")));
    }

    private RefreshToken token(String hash, boolean remember, Instant expires) {
        var t = new RefreshToken();
        t.setTokenHash(hash);
        t.setUser(user);
        t.setFamilyId(family);
        t.setExpiresAt(expires);
        t.setRememberMe(remember);
        return t;
    }

    private static User user() {
        var u = new User();
        u.setId(1L);
        u.setRole(Role.USER);
        u.setStatus(UserStatus.ACTIVE);
        return u;
    }
}
