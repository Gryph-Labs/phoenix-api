package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.auth.exception.UserAlreadyExistsException;
import com.gryphlabs.phoenix.api.auth.mapper.UserMapper;
import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.PendingRegistration;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegistrationConfirmRequest;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceRegistrationTest {
    @Spy MessageMapper messageMapper = new MessageMapper();
    private static final String EMAIL = "person@example.com";

    @Mock private CredentialService credentialService;
    @Mock private UserRepository userRepository;
    @Mock private PendingRegistrationService pendingRegistrationService;
    @Mock private EmailDeliveryService emailDeliveryService;
    @Mock private PasswordValidator passwordValidator;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private UserMapper userMapper;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void registerCreatesPendingRegistrationWithoutProcessingPassword() {
        when(credentialService.normalizeEmail(" Person@Example.com ")).thenReturn(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(pendingRegistrationService.issue(EMAIL, "Mike"))
                .thenReturn(new PendingRegistrationService.IssuedSetupToken("raw-token", pending(EMAIL, "Mike")));

        var response = authenticationService.register(request(" Person@Example.com ", "Mike"));

        verify(credentialService, never()).process(any(), any());
        verify(pendingRegistrationService).issue(EMAIL, "Mike");
        verify(emailDeliveryService).sendRegistrationVerificationEmail(
                EMAIL, "Mike", "http://localhost:8081/auth/register/confirm?token=raw-token");
        verify(userRepository, never()).save(any(User.class));
        assertEquals("Check your email to finish creating your account.", response.getMessage());
    }

    @Test
    void activeDuplicateReturnsConflict() {
        when(credentialService.normalizeEmail(EMAIL)).thenReturn(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(activeUser()));

        assertThrows(UserAlreadyExistsException.class,
                () -> authenticationService.register(request(EMAIL, "Mike")));
        verify(pendingRegistrationService, never()).issue(any(), any());
    }

    @Test
    void confirmationValidatesEncodesAndCreatesActiveUserThenConsumesPendingRegistration() {
        var pending = pending(EMAIL, "Mike");
        var user = new User(null, "person@example.com", "Mike", "encoded-password", Role.USER, UserStatus.ACTIVE, true, true, true);
        when(pendingRegistrationService.findValid("raw-token")).thenReturn(pending);
        when(passwordEncoder.encode("Valid1")).thenReturn("encoded-password");
        when(userMapper.mapPendingRegistrationToUser(any(PendingRegistration.class), any(String.class))).thenReturn(user);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        authenticationService.confirmRegistration(confirmRequest("raw-token", "Valid1"));

        verify(passwordValidator).validate("Valid1");
        verify(passwordEncoder).encode("Valid1");
        var savedUser = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUser.capture());
        assertEquals(EMAIL, savedUser.getValue().getEmail());
        assertEquals("Mike", savedUser.getValue().getDisplayName());
        assertEquals("encoded-password", savedUser.getValue().getPassword());
        assertEquals(UserStatus.ACTIVE, savedUser.getValue().getStatus());
        verify(pendingRegistrationService).consume(pending);
    }

    @Test
    void invalidPendingTokenPreventsPasswordProcessing() {
        when(pendingRegistrationService.findValid("bad-token"))
                .thenThrow(new InvalidVerificationTokenException());

        assertThrows(InvalidVerificationTokenException.class,
                () -> authenticationService.confirmRegistration(confirmRequest("bad-token", "Valid1")));
        verify(passwordValidator, never()).validate(any());
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(any(User.class));
    }

    private RegisterRequest request(String email, String displayName) {
        var request = new RegisterRequest();
        request.setEmail(email);
        request.setDisplayName(displayName);
        return request;
    }

    private RegistrationConfirmRequest confirmRequest(String token, String password) {
        var request = new RegistrationConfirmRequest();
        request.setToken(token);
        request.setPassword(password);
        return request;
    }

    private PendingRegistration pending(String email, String displayName) {
        var pending = new PendingRegistration();
        pending.setEmail(email);
        pending.setDisplayName(displayName);
        pending.setTokenHash("stored-hash");
        pending.setExpiresAt(Instant.now().plusSeconds(3600));
        return pending;
    }

    private User activeUser() {
        var user = new User();
        user.setEmail(EMAIL);
        user.setDisplayName("Mike");
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }
}
