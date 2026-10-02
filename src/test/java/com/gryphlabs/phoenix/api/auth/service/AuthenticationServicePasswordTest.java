package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.PasswordActionToken;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordResetConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordResetRequest;
import com.gryphlabs.phoenix.api.repository.PasswordActionTokenRepository;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServicePasswordTest {
    @Spy
    MessageMapper messageMapper = new MessageMapper();
    @Mock
    CredentialService credentials;
    @Mock
    UserRepository users;
    @Mock
    PendingRegistrationService pending;
    @Mock
    EmailDeliveryService email;
    @Mock
    PasswordValidator validator;
    @Mock
    PasswordEncoder encoder;
    @Mock
    JwtService jwt;
    @Mock
    RefreshTokenService refresh;
    @Mock
    ServiceClientRepository clients;
    @Mock
    PasswordActionTokenService actions;
    @Mock
    PasswordActionTokenRepository actionRepository;
    @InjectMocks
    AuthenticationService service;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(service, "passwordActionTokenExpiration", Duration.ofHours(1));
        ReflectionTestUtils.setField(service, "passwordChangeUrl", "http://change?token={token}");
        ReflectionTestUtils.setField(service, "passwordResetUrl", "http://reset?token={token}");
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void humanChangeRequestEmailsCurrentAddressAndServiceIsRejected() {
        var user = user(7L);
        lenient().when(users.findById(7L)).thenReturn(Optional.of(user));
        lenient().when(actions.issue(user, PasswordActionToken.Purpose.CHANGE, Duration.ofHours(1))).thenReturn(new PasswordActionTokenService.Issued("raw", new PasswordActionToken()));
        authenticate("7", "user");
        var response = service.requestPasswordChange();
        assertEquals("Check your email for a link to change your password.", response.getMessage());
        verify(email).sendPasswordChangeEmail("current@example.com", "Current", "http://change?token=raw");
        authenticate("7", "service");
        var serviceFailure = assertThrows(org.springframework.security.authentication.BadCredentialsException.class,
                service::requestPasswordChange);
        assertEquals("This operation is only available to user accounts.", serviceFailure.getMessage());
    }

    @Test
    void resetIsEnumerationSafeAndOnlyActiveUsersReceiveEmail() {
        when(credentials.normalizeEmail(" Person@Example.com ")).thenReturn("person@example.com");
        when(users.findByEmail("person@example.com")).thenReturn(Optional.empty());
        var first = service.requestPasswordReset(new PasswordResetRequest(" Person@Example.com "));
        assertEquals("If an account exists for that email, a password reset link has been sent.", first.getMessage());
        verify(email, never()).sendPasswordResetEmail(any(), any(), any());
        var user = user(7L);
        when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(actions.issue(user, PasswordActionToken.Purpose.RESET, Duration.ofHours(1))).thenReturn(new PasswordActionTokenService.Issued("raw", new PasswordActionToken()));
        service.requestPasswordReset(new PasswordResetRequest(" Person@Example.com "));
        verify(email).sendPasswordResetEmail("current@example.com", "Current", "http://reset?token=raw");
    }

    @Test
    void confirmConsumesPurposeBoundTokenChangesPasswordAndRevokesRefreshes() {
        var user = user(7L);
        var token = new PasswordActionToken();
        token.setUser(user);
        token.setPurpose(PasswordActionToken.Purpose.RESET);
        token.setExpiresAt(Instant.now().plusSeconds(100));
        when(actions.find("raw")).thenReturn(Optional.of(token));
        when(encoder.encode("Newpass1")).thenReturn("encoded");
        service.confirmPasswordReset(new PasswordResetConfirmRequest("raw", "Newpass1"));
        assertEquals("encoded", user.getPassword());
        assertTrue(token.isConsumed());
        verify(refresh).revokeUser(7L);
        verify(actionRepository).save(token);
        assertThrows(InvalidVerificationTokenException.class, () -> service.confirmPasswordChange(new PasswordChangeConfirmRequest("raw", "Newpass1")));
    }

    @Test
    void expiredTokenIsRejected() {
        var token = new PasswordActionToken();
        token.setPurpose(PasswordActionToken.Purpose.CHANGE);
        token.setExpiresAt(Instant.now().minusSeconds(1));
        when(actions.find("raw")).thenReturn(Optional.of(token));
        assertThrows(InvalidVerificationTokenException.class, () -> service.confirmPasswordChange(new PasswordChangeConfirmRequest("raw", "Newpass1")));
        verify(encoder, never()).encode(any());
    }

    private User user(long id) {
        var u = new User();
        u.setId(id);
        u.setEmail("current@example.com");
        u.setDisplayName("Current");
        u.setStatus(UserStatus.ACTIVE);
        u.setRole(Role.USER);
        return u;
    }

    private void authenticate(String principal, String actor) {
        var a = mock(Authentication.class);
        when(a.isAuthenticated()).thenReturn(true);
        when(a.getName()).thenReturn(principal);
        when(a.getCredentials()).thenReturn(actor);
        SecurityContextHolder.getContext().setAuthentication(a);
    }
}
