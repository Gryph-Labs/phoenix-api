package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.EmailAlreadyExistsException;
import com.gryphlabs.phoenix.api.auth.exception.InvalidEmailChangeException;
import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.auth.exception.UserAlreadyExistsException;
import com.gryphlabs.phoenix.api.auth.mapper.UserMapper;
import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.mapper.TokenMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.PasswordActionToken.Purpose;
import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.AccessTokenResponse;
import com.gryphlabs.phoenix.api.generated.auth.model.EmailChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.EmailChangeRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LogoutRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.MessageResponse;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordResetConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordResetRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegistrationConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.ServiceTokenRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.TokenResponse;
import com.gryphlabs.phoenix.api.repository.PasswordActionTokenRepository;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final CredentialService credentialService;
    private final UserRepository userRepository;
    private final PendingRegistrationService pendingRegistrationService;
    private final EmailDeliveryService emailDeliveryService;
    private final PasswordValidator passwordValidator;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final ServiceClientRepository serviceClientRepository;
    private final PasswordActionTokenService passwordActionTokenService;
    private final PasswordActionTokenRepository passwordActionTokenRepository;
    private final EmailChangeTokenService emailChangeTokenService;

    private final UserMapper userMapper;
    private final TokenMapper tokenMapper;
    private final MessageMapper messageMapper;

    @Value("${app.security.jwt.refresh-token-expiration}")
    private Duration refreshTokenExpiration;
    @Value("${app.security.jwt.remember-me-refresh-token-expiration}")
    private Duration rememberMeRefreshTokenExpiration;
    @Value("${app.security.password-action-token-expiration:1h}")
    private Duration passwordActionTokenExpiration;
    @Value("${app.security.password-action-change-url:http://localhost:8081/auth/password/change-confirm?token={token}}")
    private String passwordChangeUrl;
    @Value("${app.security.password-reset-url:http://localhost:8081/auth/password/reset/confirm?token={token}}")
    private String passwordResetUrl;
    @Value("${app.security.email-change-token-expiration:1h}")
    private Duration emailChangeTokenExpiration;
    @Value("${app.security.email-change-url:http://localhost:8081/auth/email/change-confirm?token={token}}")
    private String emailChangeUrl;
    @Value("${app.security.registration.verification-url:}")
    private String verificationUrl = "http://localhost:8081/auth/register/confirm?token={token}";

    @Transactional
    public MessageResponse register(@NonNull RegisterRequest registerRequest) {
        var normalizedEmail = credentialService.normalizeEmail(registerRequest.getEmail());
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new UserAlreadyExistsException();
        }

        sendSetupEmail(normalizedEmail, registerRequest.getDisplayName());
        return registrationAcceptedResponse();
    }

    @Transactional
    public void confirmRegistration(@NonNull RegistrationConfirmRequest registrationConfirmRequest) {
        var pendingRegistration = pendingRegistrationService.findValid(registrationConfirmRequest.getToken());
        passwordValidator.validate(registrationConfirmRequest.getPassword());

        var user = userMapper.mapPendingRegistrationToUser(
                pendingRegistration,
                passwordEncoder.encode(registrationConfirmRequest.getPassword()));

        userRepository.save(user);
        pendingRegistrationService.consume(pendingRegistration);
    }

    private void sendSetupEmail(String email, String displayName) {
        var issuedToken = pendingRegistrationService.issue(email, displayName);
        var link = verificationUrl.replace("{token}", issuedToken.rawToken());
        emailDeliveryService.sendRegistrationVerificationEmail(email, displayName, link);
    }

    @NonNull
    private MessageResponse registrationAcceptedResponse() {
        return messageMapper.of("Check your email to finish creating your account.");
    }

    @Transactional
    public TokenResponse login(@NonNull LoginRequest loginRequest) {
        var normalizedEmail = credentialService.normalizeEmail(loginRequest.getEmail());
        var user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        if (user.getStatus() != UserStatus.ACTIVE ||
                !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        var accessToken = jwtService.createAccessToken(user);
        var lifetime = Boolean.TRUE.equals(loginRequest.getRememberMe())
                ? rememberMeRefreshTokenExpiration : refreshTokenExpiration;
        var refreshToken = refreshTokenService.issue(user, lifetime, Boolean.TRUE.equals(loginRequest.getRememberMe()));
        return tokenMapper.toTokenResponse(accessToken, refreshToken, jwtService.accessLifetime(), lifetime);
    }

    @Transactional
    public TokenResponse refresh(@NonNull RefreshRequest refreshRequest) {
        var token = refreshTokenService.findForUpdate(refreshRequest.getRefreshToken())
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
        if (token.isRevoked()) {
            refreshTokenService.revokeFamily(token.getFamilyId());
            throw new BadCredentialsException("Invalid refresh token");
        }
        if (token.getExpiresAt().isBefore(Instant.now()) || token.getUser().getStatus() != UserStatus.ACTIVE) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        var user = token.getUser();
        refreshTokenService.revoke(token);

        var lifetime = token.isRememberMe() ? rememberMeRefreshTokenExpiration : refreshTokenExpiration;
        var accessToken = jwtService.createAccessToken(user);
        var replacement = refreshTokenService.issue(user, lifetime, token.isRememberMe(), token.getFamilyId());
        return tokenMapper.toTokenResponse(accessToken, replacement, jwtService.accessLifetime(), lifetime);
    }

    @Transactional
    public void logout(@NonNull LogoutRequest logoutRequest) {
        refreshTokenService.findForUpdate(logoutRequest.getRefreshToken())
                .ifPresent(token -> refreshTokenService.revokeFamilyInCurrentTransaction(token.getFamilyId()));
    }

    @Transactional
    public void requestEmailChange(EmailChangeRequest emailChangeRequest) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || !"user".equals(auth.getCredentials())) {
            throw new BadCredentialsException("Invalid authentication");
        }

        var user = userRepository.findById(Long.valueOf(auth.getName()))
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new BadCredentialsException("This operation is only available to user accounts."));
        var newEmail = credentialService.normalizeEmail(emailChangeRequest.getNewEmail());
        if (newEmail.equals(user.getEmail())) {
            throw new InvalidEmailChangeException();
        }

        if (!passwordEncoder.matches(emailChangeRequest.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }
        if (userRepository.findByEmail(newEmail)
                .filter(other ->
                        !other.getId().equals(user.getId()))
                .isPresent()) {
            throw new EmailAlreadyExistsException();
        }

        var issued = emailChangeTokenService.issue(user, newEmail, emailChangeTokenExpiration);
        emailDeliveryService.sendEmailChangeEmail(
                newEmail,
                user.getDisplayName(),
                emailChangeUrl.replace("{token}", issued.rawToken()));
    }

    @Transactional
    public void confirmEmailChange(@NonNull EmailChangeConfirmRequest emailChangeConfirmRequest) {
        var token = emailChangeTokenService.find(emailChangeConfirmRequest.getToken())
                .filter(t ->
                        !t.isConsumed() && t.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(InvalidEmailChangeException::new);
        if (userRepository.findByEmail(token.getProposedEmail())
                .filter(other ->
                        !other.getId().equals(token.getUser().getId()))
                .isPresent()) {
            throw new EmailAlreadyExistsException();
        }

        token.getUser().setEmail(token.getProposedEmail());
        token.setConsumed(true);
        userRepository.save(token.getUser());
        emailChangeTokenService.consume(token);
        refreshTokenService.revokeUser(token.getUser().getId());
    }

    public MessageResponse requestPasswordChange() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                !"user".equals(authentication.getCredentials())) {
            throw new BadCredentialsException("This operation is only available to user accounts.");
        }

        var user = userRepository.findById(Long.valueOf(authentication.getName()))
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new BadCredentialsException("This operation is only available to user accounts."));
        var issued = passwordActionTokenService.issue(user, Purpose.CHANGE, passwordActionTokenExpiration);
        emailDeliveryService.sendPasswordChangeEmail(
                user.getEmail(),
                user.getDisplayName(),
                passwordChangeUrl.replace("{token}", issued.rawToken()));
        return messageMapper.of("Check your email for a link to change your password.");
    }

    @Transactional
    public void confirmPasswordChange(@NonNull PasswordChangeConfirmRequest passwordChangeConfirmRequest) {
        confirmPasswordAction(
                passwordChangeConfirmRequest.getToken(),
                passwordChangeConfirmRequest.getNewPassword(),
                Purpose.CHANGE);
    }

    public AccessTokenResponse issueServiceToken(@NonNull ServiceTokenRequest serviceTokenRequest) {
        if (serviceTokenRequest.getGrantType() != ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS) {
            throw new BadCredentialsException("Invalid service credentials");
        }

        var client = serviceClientRepository.findByClientId(serviceTokenRequest.getClientId())
                .filter(ServiceClient::isEnabled).filter(clientRecord -> !clientRecord.isRevoked())
                .orElseThrow(() -> new BadCredentialsException("Invalid service credentials"));
        if (!passwordEncoder.matches(serviceTokenRequest.getClientSecret(), client.getClientSecretHash())) {
            throw new BadCredentialsException("Invalid service credentials");
        }

        return tokenMapper.toAccessTokenResponse(jwtService.createAccessToken(client), jwtService.accessLifetime());
    }

    public MessageResponse requestPasswordReset(@NonNull PasswordResetRequest passwordResetRequest) {
        var normalized = credentialService.normalizeEmail(passwordResetRequest.getEmail());
        userRepository.findByEmail(normalized).
                filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .ifPresent(user -> {
                    var issued = passwordActionTokenService.issue(user, Purpose.RESET, passwordActionTokenExpiration);
                    emailDeliveryService.sendPasswordResetEmail(
                            user.getEmail(),
                            user.getDisplayName(),
                            passwordResetUrl.replace("{token}", issued.rawToken()));
                });
        return messageMapper.of("If an account exists for that email, a password reset link has been sent.");
    }

    @Transactional
    public void confirmPasswordReset(@NonNull PasswordResetConfirmRequest passwordResetConfirmRequest) {
        confirmPasswordAction(
                passwordResetConfirmRequest.getToken(),
                passwordResetConfirmRequest.getNewPassword(),
                Purpose.RESET);
    }

    private void confirmPasswordAction(String rawToken, String newPassword, Purpose purpose) {
        var action = passwordActionTokenService.find(rawToken)
                .filter(t ->
                        t.getPurpose() == purpose && !t.isConsumed() && t.getExpiresAt()
                                .isAfter(Instant.now()))
                .orElseThrow(InvalidVerificationTokenException::new);
        passwordValidator.validate(newPassword);

        action.getUser().setPassword(passwordEncoder.encode(newPassword));
        action.setConsumed(true);
        userRepository.save(action.getUser());
        passwordActionTokenRepository.save(action);
        refreshTokenService.revokeUser(action.getUser().getId());
    }
}
