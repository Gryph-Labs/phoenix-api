package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Set;

@Service
public class CallerAuthorizationStateService {
    private static final String KEY_PREFIX = "phoenix:auth:caller:";
    private final ServiceClientRepository clients;
    private final StringRedisTemplate redis;
    private final Duration ttl;
    private final AuthMetrics metrics;

    public CallerAuthorizationStateService(ServiceClientRepository clients, StringRedisTemplate redis,
                                           @Value("${app.security.caller-authorization.cache-ttl:5m}") Duration ttl,
                                           AuthMetrics metrics) {
        this.clients = clients;
        this.redis = redis;
        this.ttl = ttl;
        this.metrics = metrics;
    }

    public AuthorizationState resolve(long callerId) {
        metrics.count("authorization.attempts");
        var timer = metrics.startTimer();
        try {
            String cached = null;
            try {
                cached = redis.opsForValue().get(key(callerId));
            } catch (RuntimeException ex) {
                metrics.count("cache.redis_error");
                metrics.count("cache.postgresql_fallback");
            }
            if (cached != null) {
                metrics.count("cache.hit");
                return record(cached);
            }
            metrics.count("cache.miss");
            AuthorizationState state;
            try {
                state = clients.findWithOwnerById(callerId).map(this::derive)
                        .orElse(AuthorizationState.denied("caller_missing"));
            } catch (RuntimeException ex) {
                metrics.count("authorization.denied", "authorization_state_unavailable");
                return AuthorizationState.denied("authorization_state_unavailable");
            }
            try {
                redis.opsForValue().set(key(callerId), state.reason(), ttl);
                metrics.count("cache.population");
            } catch (RuntimeException ex) {
                metrics.count("cache.redis_error");
            }
            return state;
        } finally {
            metrics.stop(timer, "authorization.latency");
        }
    }

    public void invalidateCaller(long callerId) {
        invalidateKey(key(callerId));
    }

    public void invalidateUser(long userId) {
        List<ServiceClient> owned;
        try {
            owned = clients.findByOwnerId(userId);
        } catch (RuntimeException ex) {
            metrics.count("cache.invalidation_failure");
            return;
        }
        owned.forEach(client -> invalidateCaller(client.getId()));
    }

    private void invalidateKey(String key) {
        try {
            redis.delete(key);
            metrics.count("cache.explicit_invalidation");
        } catch (RuntimeException ex) {
            metrics.count("cache.invalidation_failure");
        }
    }

    private AuthorizationState derive(ServiceClient client) {
        if (client.getOwner() == null) {
            return AuthorizationState.denied("authorization_state_unavailable");
        }
        if (client.getOwner().getStatus() != UserStatus.ACTIVE) {
            return AuthorizationState.denied("owner_disabled");
        }
        if (!client.isEnabled()) {
            return AuthorizationState.denied("caller_disabled");
        }
        if (client.isRevoked()) {
            return AuthorizationState.denied("caller_revoked");
        }
        return AuthorizationState.authorized(client.getAuthorities());
    }

    private AuthorizationState record(String reason) {
        var parts = reason.split("\\|", -1);
        if ("allowed".equals(parts[0])) {
            return AuthorizationState.authorized(parts.length == 1 ? Set.of() : Set.of(parts[1].split(",")));
        }
        return AuthorizationState.denied(parts[0]);
    }

    private String key(long callerId) {
        return KEY_PREFIX + callerId;
    }

    public record AuthorizationState(boolean allowed, String reason, Set<String> authorities) {
        static AuthorizationState authorized(Set<String> authorities) {
            return new AuthorizationState(true, "allowed|" + String.join(",", authorities), Set.copyOf(authorities));
        }

        static AuthorizationState denied(String reason) {
            return new AuthorizationState(false, reason, Set.of());
        }
    }
}
