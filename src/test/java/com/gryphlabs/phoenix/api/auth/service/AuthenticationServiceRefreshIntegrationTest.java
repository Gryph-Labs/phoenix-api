package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@ActiveProfiles("local")
class AuthenticationServiceRefreshIntegrationTest {
    @Autowired AuthenticationService authenticationService;
    @Autowired UserRepository userRepository;
    @Autowired PasswordEncoder passwordEncoder;

    @Test
    void replayingRotatedTokenRevokesTheCurrentTokenFamily() {
        var user = new User();
        user.setEmail("refresh-replay@example.com");
        user.setDisplayName("Refresh Replay");
        user.setPassword(passwordEncoder.encode("Password1"));
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        var tokenA = authenticationService.login(new LoginRequest("refresh-replay@example.com", "Password1"))
                .getRefreshToken();
        var tokenB = authenticationService.refresh(new RefreshRequest(tokenA)).getRefreshToken();

        assertThrows(BadCredentialsException.class,
                () -> authenticationService.refresh(new RefreshRequest(tokenA)));
        assertThrows(BadCredentialsException.class,
                () -> authenticationService.refresh(new RefreshRequest(tokenB)));
    }
}
