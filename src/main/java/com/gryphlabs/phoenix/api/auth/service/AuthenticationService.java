package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.generated.auth.model.EmailChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LogoutRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.PasswordChangeConfirmRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RegisterResponse;
import com.gryphlabs.phoenix.api.generated.auth.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final CredentialService credentialService;

    public RegisterResponse register(RegisterRequest registerRequest) {
        var credentials = credentialService.process(registerRequest.getEmail(), registerRequest.getPassword());
        return null;
    }

    public TokenResponse login(LoginRequest loginRequest) {
        return null;
    }

    public TokenResponse refresh(RefreshRequest refreshRequest) {
        return null;
    }

    public void logout(LogoutRequest logoutRequest) {
    }

    public void requestEmailChange() {
    }

    public void confirmEmailChange(EmailChangeConfirmRequest emailChangeConfirmRequest) {
    }

    public void requestPasswordChange() {
    }

    public void confirmPasswordChange(PasswordChangeConfirmRequest passwordChangeConfirmRequest) {
    }
}
