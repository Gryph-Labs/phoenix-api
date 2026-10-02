package com.gryphlabs.phoenix.api.auth.service;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthMetricsTest {
    @Test
    void metricsUseOnlyBoundedCategoryTags() {
        var registry = new SimpleMeterRegistry();
        var metrics = new AuthMetrics(registry);
        metrics.count("authorization.attempts");
        metrics.count("authorization.denied", "owner_disabled");
        metrics.count("cache.hit");
        metrics.count("service_token.success");
        var sample = metrics.startTimer();
        metrics.stop(sample, "authorization.latency");
        registry.forEachMeter(meter -> {
            assertFalse(meter.getId().getTags().stream().anyMatch(tag ->
                    tag.getValue().matches(".*(user|caller|client|email|token|secret|authorization|payload|jwt).*")));
            assertTrue(meter.getId().getTags().stream().allMatch(tag -> "category".equals(tag.getKey())));
        });
    }
}
