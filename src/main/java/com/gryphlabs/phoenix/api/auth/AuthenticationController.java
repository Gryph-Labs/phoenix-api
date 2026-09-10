package com.gryphlabs.phoenix.api.auth;

import com.gryphlabs.phoenix.api.auth.service.AuthenticationService;
import com.gryphlabs.phoenix.api.generated.auth.api.AuthenticationApi;
import com.gryphlabs.phoenix.api.generated.auth.model.EmailChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LogoutRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterResponse;
import com.gryphlabs.phoenix.api.generated.auth.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthenticationController implements AuthenticationApi {
    private final AuthenticationService authenticationService;

    @Override
    public ResponseEntity<RegisterResponse> register(RegisterRequest registerRequest) {
        var response = authenticationService.register(registerRequest);
        return ResponseEntity.ok(response);
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
        return ResponseEntity.ok().build();
    }

    @Override
    public ResponseEntity<Void> requestEmailChange() {
        authenticationService.requestEmailChange();
        return ResponseEntity.ok().build();
    }

    @Override
    public ResponseEntity<Void> confirmEmailChange(EmailChangeConfirmRequest emailChangeConfirmRequest) {
        authenticationService.confirmEmailChange(emailChangeConfirmRequest);
        return ResponseEntity.ok().build();
    }

    @Override
    public ResponseEntity<Void> requestPasswordChange() {
        authenticationService.requestPasswordChange();
        return ResponseEntity.ok().build();
    }

    @Override
    public ResponseEntity<Void> confirmPasswordChange(PasswordChangeConfirmRequest passwordChangeConfirmRequest) {
        authenticationService.confirmPasswordChange(passwordChangeConfirmRequest);
        return ResponseEntity.ok().build();
    }
}
