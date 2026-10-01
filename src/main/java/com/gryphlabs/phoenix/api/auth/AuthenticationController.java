package com.gryphlabs.phoenix.api.auth;

import com.gryphlabs.phoenix.api.auth.service.AuthenticationService;
import com.gryphlabs.phoenix.api.generated.auth.api.AuthenticationApi;
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
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpStatus.ACCEPTED;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequiredArgsConstructor
public class AuthenticationController implements AuthenticationApi {
    private final AuthenticationService authenticationService;

    @Override
    public ResponseEntity<MessageResponse> register(RegisterRequest registerRequest) {
        var response = authenticationService.register(registerRequest);
        return new ResponseEntity<>(response, ACCEPTED);
    }

    @Override
    public ResponseEntity<Void> confirmRegistration(RegistrationConfirmRequest registrationConfirmRequest) {
        authenticationService.confirmRegistration(registrationConfirmRequest);
        return new ResponseEntity<>(NO_CONTENT);
    }

    @Override
    public ResponseEntity<TokenResponse> login(LoginRequest loginRequest) {
        var response = authenticationService.login(loginRequest);
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<TokenResponse> refresh(RefreshRequest refreshRequest) {
        var response = authenticationService.refresh(refreshRequest);
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<Void> logout(LogoutRequest logoutRequest) {
        authenticationService.logout(logoutRequest);
        return new ResponseEntity<>(NO_CONTENT);
    }

    @Override
    public ResponseEntity<Void> requestEmailChange(EmailChangeRequest emailChangeRequest) {
        authenticationService.requestEmailChange(emailChangeRequest);
        return new ResponseEntity<>(ACCEPTED);
    }

    @Override
    public ResponseEntity<Void> confirmEmailChange(EmailChangeConfirmRequest emailChangeConfirmRequest) {
        authenticationService.confirmEmailChange(emailChangeConfirmRequest);
        return new ResponseEntity<>(NO_CONTENT);
    }

    @Override
    public ResponseEntity<MessageResponse> requestPasswordChange() {
        var response = authenticationService.requestPasswordChange();
        return new ResponseEntity<>(response, ACCEPTED);
    }

    @Override
    public ResponseEntity<Void> confirmPasswordChange(PasswordChangeConfirmRequest passwordChangeConfirmRequest) {
        authenticationService.confirmPasswordChange(passwordChangeConfirmRequest);
        return new ResponseEntity<>(NO_CONTENT);
    }

    @Override
    public ResponseEntity<AccessTokenResponse> issueServiceToken(ServiceTokenRequest serviceTokenRequest) {
        var response = authenticationService.issueServiceToken(serviceTokenRequest);
        return new ResponseEntity<>(response, OK);
    }

    @Override
    public ResponseEntity<MessageResponse> requestPasswordReset(PasswordResetRequest passwordResetRequest) {
        var response = authenticationService.requestPasswordReset(passwordResetRequest);
        return new ResponseEntity<>(response, ACCEPTED);
    }

    @Override
    public ResponseEntity<Void> confirmPasswordReset(PasswordResetConfirmRequest passwordResetConfirmRequest) {
        authenticationService.confirmPasswordReset(passwordResetConfirmRequest);
        return new ResponseEntity<>(NO_CONTENT);
    }
}
