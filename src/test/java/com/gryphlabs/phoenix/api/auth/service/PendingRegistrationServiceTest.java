package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.exception.InvalidVerificationTokenException;
import com.gryphlabs.phoenix.api.entity.PendingRegistration;
import com.gryphlabs.phoenix.api.repository.PendingRegistrationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PendingRegistrationServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-30T12:00:00Z");

    @Mock
    private PendingRegistrationRepository pendingRegistrationRepository;

    private PendingRegistrationService pendingRegistrationService;

    @BeforeEach
    void setUp() {
        pendingRegistrationService = new PendingRegistrationService(
                pendingRegistrationRepository, Clock.fixed(NOW, ZoneOffset.UTC));
        ReflectionTestUtils.setField(pendingRegistrationService, "tokenExpiration", Duration.ofHours(1));
    }

    @Test
    void storesOnlyAHashOfTheRawTokenAndPersistsSignupData() {
        when(pendingRegistrationRepository.findByEmail("person@example.com"))
                .thenReturn(Optional.empty());

        var issued = pendingRegistrationService.issue("person@example.com", "Mike");

        var saved = ArgumentCaptor.forClass(PendingRegistration.class);
        verify(pendingRegistrationRepository).save(saved.capture());
        assertEquals("person@example.com", saved.getValue().getEmail());
        assertEquals("Mike", saved.getValue().getDisplayName());
        assertNotEquals(issued.rawToken(), saved.getValue().getTokenHash());
        assertEquals(pendingRegistrationService.hashForStorage(issued.rawToken()), saved.getValue().getTokenHash());
        assertEquals(NOW.plus(Duration.ofHours(1)), saved.getValue().getExpiresAt());
    }

    @Test
    void updatesExistingPendingRegistrationAndReplacesItsToken() {
        var existing = new PendingRegistration();
        existing.setEmail("person@example.com");
        existing.setDisplayName("Old Name");
        existing.setTokenHash("old-hash");
        existing.setExpiresAt(NOW.plusSeconds(30));
        when(pendingRegistrationRepository.findByEmail(existing.getEmail())).thenReturn(Optional.of(existing));

        var issued = pendingRegistrationService.issue(existing.getEmail(), "New Name");

        assertEquals(existing, issued.pendingRegistration());
        assertEquals("New Name", existing.getDisplayName());
        assertNotEquals("old-hash", existing.getTokenHash());
        verify(pendingRegistrationRepository).save(existing);
    }

    @Test
    void rejectsExpiredAndUnknownTokens() {
        var expired = new PendingRegistration();
        expired.setTokenHash("expired-hash");
        expired.setExpiresAt(NOW.minusSeconds(1));
        when(pendingRegistrationRepository.findByTokenHash(any())).thenReturn(Optional.of(expired));
        assertThrows(InvalidVerificationTokenException.class,
                () -> pendingRegistrationService.findValid("raw-token"));

        when(pendingRegistrationRepository.findByTokenHash(any())).thenReturn(Optional.empty());
        assertThrows(InvalidVerificationTokenException.class,
                () -> pendingRegistrationService.findValid("raw-token"));
    }

    @Test
    void consumingPendingRegistrationDeletesIt() {
        var pending = new PendingRegistration();

        pendingRegistrationService.consume(pending);

        verify(pendingRegistrationRepository).delete(pending);
    }

    @Test
    void consumedTokenCannotBeReused() {
        var pending = new PendingRegistration();
        pendingRegistrationService.consume(pending);
        when(pendingRegistrationRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThrows(InvalidVerificationTokenException.class,
                () -> pendingRegistrationService.findValid("consumed-token"));
    }
}
