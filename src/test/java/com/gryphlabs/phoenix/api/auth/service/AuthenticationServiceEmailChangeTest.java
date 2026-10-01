package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.*;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.*;
import com.gryphlabs.phoenix.api.generated.auth.model.*;
import com.gryphlabs.phoenix.api.repository.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.*;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationServiceEmailChangeTest {
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
    PasswordActionTokenService passwordActions;
    @Mock
    PasswordActionTokenRepository passwordRepository;
    @Mock
    EmailChangeTokenService tokens;
    @InjectMocks
    AuthenticationService service;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(service, "emailChangeTokenExpiration", Duration.ofHours(1));
        ReflectionTestUtils.setField(service, "emailChangeUrl", "http://confirm?token={token}");
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void requestNormalizesReauthenticatesEmailsNewAddressAndStoresNoRawToken() {
        var u = user(1, "old@example.com");
        authenticate("1", "user");
        when(users.findById(1L)).thenReturn(Optional.of(u));
        when(credentials.normalizeEmail(" New@Example.com ")).thenReturn("new@example.com");
        when(encoder.matches("current", "hash")).thenReturn(true);
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());
        var entity = new EmailChangeToken();
        entity.setProposedEmail("new@example.com");
        when(tokens.issue(u, "new@example.com", Duration.ofHours(1))).thenReturn(new EmailChangeTokenService.Issued("raw", entity));
        service.requestEmailChange(new EmailChangeRequest(" New@Example.com ", "current"));
        verify(encoder).matches("current", "hash");
        verify(email).sendEmailChangeEmail("new@example.com", "Alice", "http://confirm?token=raw");
        assertNotEquals("raw", entity.getTokenHash());
        assertEquals("new@example.com", entity.getProposedEmail());
    }

    @Test
    void wrongPasswordSameEmailDuplicateUnauthenticatedAndServiceAreRejected() {
        var u = user(1, "old@example.com");
        when(users.findById(1L)).thenReturn(Optional.of(u));
        authenticate("1", "user");
        when(credentials.normalizeEmail(anyString())).thenReturn("new@example.com");
        when(encoder.matches(anyString(), anyString())).thenReturn(false);
        assertThrows(BadCredentialsException.class, () -> service.requestEmailChange(new EmailChangeRequest("new@example.com", "bad")));
        when(credentials.normalizeEmail(anyString())).thenReturn("old@example.com");
        assertThrows(InvalidEmailChangeException.class, () -> service.requestEmailChange(new EmailChangeRequest("old@example.com", "bad")));
        authenticate("1", "service");
        assertThrows(BadCredentialsException.class,
                () -> service.requestEmailChange(new EmailChangeRequest("new@example.com", "bad")));
        SecurityContextHolder.clearContext();
        assertThrows(BadCredentialsException.class, () -> service.requestEmailChange(new EmailChangeRequest("new@example.com", "bad")));
    }

    @Test
    void duplicateAndSecondRequestInvalidatesPrior() {
        var u = user(1, "old@example.com");
        authenticate("1", "user");
        when(users.findById(1L)).thenReturn(Optional.of(u));
        when(credentials.normalizeEmail(anyString())).thenReturn("new@example.com");
        when(encoder.matches(anyString(), anyString())).thenReturn(true);
        var other = user(2, "new@example.com");
        when(users.findByEmail("new@example.com")).thenReturn(Optional.of(other));
        assertThrows(EmailAlreadyExistsException.class, () -> service.requestEmailChange(new EmailChangeRequest("new@example.com", "ok")));
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(tokens.issue(any(), any(), any())).thenReturn(new EmailChangeTokenService.Issued("one", new EmailChangeToken()), new EmailChangeTokenService.Issued("two", new EmailChangeToken()));
        service.requestEmailChange(new EmailChangeRequest("new@example.com", "ok"));
        service.requestEmailChange(new EmailChangeRequest("new@example.com", "ok"));
        verify(tokens, times(2)).issue(u, "new@example.com", Duration.ofHours(1));
    }

    @Test
    void confirmationUsesPersistedEmailConsumesTokenRevokesOnlyUsersSessionsAndRejectsReuseOrTakenEmail() {
        var u = user(1, "old@example.com");
        var t = new EmailChangeToken();
        t.setUser(u);
        t.setProposedEmail("new@example.com");
        t.setExpiresAt(Instant.now().plusSeconds(60));
        when(tokens.find("raw")).thenReturn(Optional.of(t));
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());
        service.confirmEmailChange(new EmailChangeConfirmRequest("raw"));
        assertEquals("new@example.com", u.getEmail());
        assertTrue(t.isConsumed());
        verify(refresh).revokeUser(1L);
        verify(users).save(u);
        assertThrows(InvalidEmailChangeException.class, () -> service.confirmEmailChange(new EmailChangeConfirmRequest("raw")));
        var u2 = user(2, "other@example.com");
        var taken = new EmailChangeToken();
        taken.setUser(u2);
        taken.setProposedEmail("taken@example.com");
        taken.setExpiresAt(Instant.now().plusSeconds(60));
        var other = user(3, "taken@example.com");
        when(tokens.find("taken")).thenReturn(Optional.of(taken));
        when(users.findByEmail("taken@example.com")).thenReturn(Optional.of(other));
        assertThrows(EmailAlreadyExistsException.class, () -> service.confirmEmailChange(new EmailChangeConfirmRequest("taken")));
        assertEquals("other@example.com", u2.getEmail());
        verify(users, never()).save(u2);
    }

    @Test
    void expiredUnknownAndOtherPurposeAreRejected() {
        var u = user(1, "old@example.com");
        var t = new EmailChangeToken();
        t.setUser(u);
        t.setProposedEmail("new@example.com");
        t.setExpiresAt(Instant.now().minusSeconds(1));
        when(tokens.find("expired")).thenReturn(Optional.of(t));
        assertThrows(InvalidEmailChangeException.class, () -> service.confirmEmailChange(new EmailChangeConfirmRequest("expired")));
        when(tokens.find("unknown")).thenReturn(Optional.empty());
        assertThrows(InvalidEmailChangeException.class, () -> service.confirmEmailChange(new EmailChangeConfirmRequest("unknown")));
    }

    private User user(long id, String email) {
        var u = new User();
        u.setId(id);
        u.setEmail(email);
        u.setDisplayName("Alice");
        u.setPassword("hash");
        u.setStatus(UserStatus.ACTIVE);
        u.setRole(Role.USER);
        return u;
    }

    private void authenticate(String id, String actor) {
        var a = mock(Authentication.class);
        when(a.isAuthenticated()).thenReturn(true);
        when(a.getName()).thenReturn(id);
        when(a.getCredentials()).thenReturn(actor);
        SecurityContextHolder.getContext().setAuthentication(a);
    }
}
