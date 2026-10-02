package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Testcontainers
class CallerAuthorizationStateRedisIntegrationTest {
    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @Test
    @Timeout(30)
    void cacheMissThenHitAndExplicitInvalidationUseRealRedis() {
        var repository = mock(ServiceClientRepository.class);
        var client = client();
        when(repository.findWithOwnerById(7L)).thenReturn(Optional.of(client));
        var template = template();
        var registry = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        var metrics = new AuthMetrics(registry);
        var service = new CallerAuthorizationStateService(repository, template, Duration.ofSeconds(30), metrics);

        assertTrue(service.resolve(7L).allowed());
        assertEquals("allowed", template.opsForValue().get("phoenix:auth:caller:7"));
        assertTrue(service.resolve(7L).allowed());
        verify(repository, times(1)).findWithOwnerById(7L);
        assertEquals(1.0, registry.get("phoenix.auth.cache.miss").counter().count());
        assertEquals(1.0, registry.get("phoenix.auth.cache.hit").counter().count());
        assertEquals(1.0, registry.get("phoenix.auth.cache.population").counter().count());

        service.invalidateCaller(7L);
        assertNull(template.opsForValue().get("phoenix:auth:caller:7"));
        assertEquals(1.0, registry.get("phoenix.auth.cache.explicit_invalidation").counter().count());
        assertTrue(registry.get("phoenix.auth.authorization.latency").timer().count() >= 2);
        template.getConnectionFactory().getConnection().close();
    }

    @Test
    @Timeout(30)
    void expiryDoesNotRefreshUntilTheNextAuthorizationRequest() throws InterruptedException {
        var repository = mock(ServiceClientRepository.class);
        when(repository.findWithOwnerById(8L)).thenReturn(Optional.of(client()));
        var template = template();
        var service = new CallerAuthorizationStateService(repository, template, Duration.ofMillis(500), new AuthMetrics(new SimpleMeterRegistry()));
        assertTrue(service.resolve(8L).allowed());
        Thread.sleep(900);
        verify(repository, times(1)).findWithOwnerById(8L);
        assertTrue(service.resolve(8L).allowed());
        verify(repository, times(2)).findWithOwnerById(8L);
    }

    @Test
    void redisFailureFallsBackAndCombinedFailureDenies() {
        var repository = mock(ServiceClientRepository.class);
        when(repository.findWithOwnerById(7L)).thenReturn(Optional.of(client()));
        var redisTemplate = mock(org.springframework.data.redis.core.StringRedisTemplate.class);
        var valueOperations = mock(org.springframework.data.redis.core.ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenThrow(new IllegalStateException("redis down"));
        var registry = new SimpleMeterRegistry();
        var service = new CallerAuthorizationStateService(repository, redisTemplate, Duration.ofMinutes(5), new AuthMetrics(registry));
        assertTrue(service.resolve(7L).allowed());
        assertEquals(1.0, registry.get("phoenix.auth.cache.redis_error").counter().count());
        assertEquals(1.0, registry.get("phoenix.auth.cache.postgresql_fallback").counter().count());

        when(repository.findWithOwnerById(7L)).thenThrow(new IllegalStateException("postgres down"));
        assertFalse(service.resolve(7L).allowed());
        assertEquals("authorization_state_unavailable", service.resolve(7L).reason());
    }

    private StringRedisTemplate template() {
        var factory = new LettuceConnectionFactory(redis.getHost(), redis.getMappedPort(6379));
        factory.afterPropertiesSet();
        var template = new StringRedisTemplate(factory);
        template.afterPropertiesSet();
        template.delete("phoenix:auth:caller:7");
        return template;
    }

    private ServiceClient client() {
        var owner = new User();
        owner.setId(9L);
        owner.setStatus(UserStatus.ACTIVE);
        var client = new ServiceClient();
        client.setId(7L);
        client.setOwner(owner);
        return client;
    }
}
