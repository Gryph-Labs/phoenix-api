package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.*;
import com.gryphlabs.phoenix.api.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshTokenServiceTest {
    @Test void storesOnlyHashAndCreatesFamilyWithRequestedLifetime() {
        var repository = mock(RefreshTokenRepository.class);
        var clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        var service = new RefreshTokenService(repository, clock); var user = new User(); user.setId(42L);
        var issued = service.issue(user, Duration.ofDays(7));
        var saved = ArgumentCaptor.forClass(RefreshToken.class); verify(repository).save(saved.capture());
        var entity = saved.getValue();
        assertNotEquals(issued.rawToken(), entity.getTokenHash());
        assertEquals(RefreshTokenService.hash(issued.rawToken()), entity.getTokenHash());
        assertNotNull(entity.getFamilyId()); assertSame(user, entity.getUser());
        assertEquals(clock.instant().plus(Duration.ofDays(7)), entity.getExpiresAt());
    }
}
