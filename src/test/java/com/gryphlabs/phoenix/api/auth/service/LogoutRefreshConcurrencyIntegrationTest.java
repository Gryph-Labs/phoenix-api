package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.RefreshToken;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.LogoutRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.RefreshRequest;
import com.gryphlabs.phoenix.api.generated.auth.model.TokenResponse;
import com.gryphlabs.phoenix.api.repository.RefreshTokenRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("local")
class LogoutRefreshConcurrencyIntegrationTest {
    @Autowired
    AuthenticationService authenticationService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RefreshTokenRepository refreshTokenRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    TransactionTemplate transactionTemplate;

    @Test
    void logoutLeavesNoUsableTokenWhenItRacesWithRefresh() throws Exception {
        var user = new User();
        user.setEmail("logout-refresh-race@example.com");
        user.setDisplayName("Logout Refresh Race");
        user.setPassword(passwordEncoder.encode("Password1!"));
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        var tokenA = authenticationService.login(new LoginRequest(
                "logout-refresh-race@example.com", "Password1!")).getRefreshToken();
        var familyId = transactionTemplate.execute(status -> refreshTokenRepository
                .findByTokenHash(RefreshTokenService.hash(tokenA)).orElseThrow().getFamilyId());
        var lockAcquired = new CountDownLatch(1);
        var releaseLock = new CountDownLatch(1);

        try (ExecutorService lockExecutor = Executors.newSingleThreadExecutor();
             ExecutorService raceExecutor = Executors.newFixedThreadPool(2)) {
            var lockFuture = lockExecutor.submit(() -> transactionTemplate.execute(status -> {
                refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(tokenA)).orElseThrow();
                lockAcquired.countDown();
                await(releaseLock);
                return null;
            }));
            lockAcquired.await();

            var refreshFuture = raceExecutor.submit(() -> refresh(tokenA));
            var logoutFuture = raceExecutor.submit(() -> {
                authenticationService.logout(new LogoutRequest(tokenA));
                return null;
            });

            releaseLock.countDown();
            lockFuture.get();
            logoutFuture.get();

            TokenResponse rotated = null;
            try {
                rotated = refreshFuture.get();
            } catch (ExecutionException ex) {
                assertTrue(ex.getCause() instanceof BadCredentialsException);
            }

            var familyTokens = refreshTokenRepository.findAll().stream()
                    .filter(token -> token.getFamilyId().equals(familyId))
                    .toList();
            assertTrue(familyTokens.stream().allMatch(RefreshToken::isRevoked));
            if (rotated != null) {
                var rotatedToken = rotated.getRefreshToken();
                assertThrows(BadCredentialsException.class,
                        () -> authenticationService.refresh(new RefreshRequest(rotatedToken)));
            }
        }
    }

    private TokenResponse refresh(String token) {
        return authenticationService.refresh(new RefreshRequest(token));
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while coordinating concurrency test", ex);
        }
    }
}
