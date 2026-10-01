package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.mapper.TokenMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.*;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceLoginTest {
    @Spy TokenMapper tokenMapper = new TokenMapper();
    @Spy MessageMapper messageMapper = new MessageMapper();
    @Mock CredentialService credentials;
    @Mock UserRepository users;
    @Mock PendingRegistrationService pending;
    @Mock EmailDeliveryService mail;
    @Mock PasswordValidator validator;
    @Mock PasswordEncoder encoder;
    @Mock JwtService jwt;
    @Mock RefreshTokenService refresh;
    @InjectMocks AuthenticationService service;

    @BeforeEach void configure() {
        ReflectionTestUtils.setField(service, "refreshTokenExpiration", Duration.ofDays(7));
        ReflectionTestUtils.setField(service, "rememberMeRefreshTokenExpiration", Duration.ofDays(30));
        when(credentials.normalizeEmail(anyString())).thenAnswer(i -> i.getArgument(0, String.class).trim().toLowerCase());
        lenient().when(jwt.createAccessToken(any(User.class))).thenReturn("access");
        lenient().when(jwt.accessLifetime()).thenReturn(Duration.ofMinutes(15));
        lenient().when(refresh.issue(any(), any())).thenAnswer(i -> new RefreshTokenService.IssuedRefreshToken("refresh", new RefreshToken()));
        lenient().when(refresh.issue(any(), any(), anyBoolean())).thenAnswer(i -> new RefreshTokenService.IssuedRefreshToken("refresh", new RefreshToken()));
    }

    @Test void validNormalizedLoginReturnsCompleteTokenResponseAndPersistsRefresh() {
        var user = user(42L, UserStatus.ACTIVE); when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(encoder.matches("password", "encoded")).thenReturn(true);
        var response = service.login(request(" Person@Example.COM ", false, "password"));
        assertEquals("access", response.getAccessToken()); assertEquals("refresh", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType()); assertEquals(900L, response.getExpiresIn());
        assertEquals(604800L, response.getRefreshExpiresIn());
        verify(encoder).matches("password", "encoded");
        verify(refresh).issue(user, Duration.ofDays(7), false);
    }

    @Test void rememberMeExtendsOnlyRefreshLifetime() {
        var user = user(42L, UserStatus.ACTIVE); when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(encoder.matches(anyString(), eq("encoded"))).thenReturn(true);
        var normal = service.login(request("person@example.com", false, "password"));
        var remembered = service.login(request("person@example.com", true, "password"));
        assertEquals(normal.getExpiresIn(), remembered.getExpiresIn());
        assertEquals(604800L, normal.getRefreshExpiresIn()); assertEquals(2592000L, remembered.getRefreshExpiresIn());
        verify(refresh).issue(user, Duration.ofDays(30), true);
    }

    @Test void unknownWrongPasswordAndDisabledAreSameGenericFailure() {
        when(users.findByEmail("missing@example.com")).thenReturn(Optional.empty());
        var unknown = assertThrows(BadCredentialsException.class, () -> service.login(request("missing@example.com", false, "bad")));
        var user = user(42L, UserStatus.ACTIVE); when(users.findByEmail("person@example.com")).thenReturn(Optional.of(user));
        when(encoder.matches("bad", "encoded")).thenReturn(false);
        var wrong = assertThrows(BadCredentialsException.class, () -> service.login(request("person@example.com", false, "bad")));
        user.setStatus(UserStatus.DISABLED);
        var disabled = assertThrows(BadCredentialsException.class, () -> service.login(request("person@example.com", false, "bad")));
        assertEquals(unknown.getMessage(), wrong.getMessage()); assertEquals(wrong.getMessage(), disabled.getMessage());
        verify(encoder, times(1)).matches("bad", "encoded");
    }

    private LoginRequest request(String email, boolean remember, String password) {
        var r = new LoginRequest(email, password); r.setRememberMe(remember); return r;
    }
    private User user(Long id, UserStatus status) {
        var u = new User(); u.setId(id); u.setEmail("person@example.com"); u.setPassword("encoded");
        u.setDisplayName("Person"); u.setRole(Role.USER); u.setStatus(status); return u;
    }
}
