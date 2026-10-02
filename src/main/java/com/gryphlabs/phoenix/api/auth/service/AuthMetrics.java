package com.gryphlabs.phoenix.api.auth.service;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

@Component
public class AuthMetrics {
    private final MeterRegistry registry;

    public AuthMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void count(String name) {
        registry.counter("phoenix.auth." + name).increment();
    }

    public void count(String name, String category) {
        registry.counter("phoenix.auth." + name, "category", category).increment();
    }

    public Timer.Sample startTimer() {
        return Timer.start(registry);
    }

    public void stop(Timer.Sample sample, String name) {
        sample.stop(registry.timer("phoenix.auth." + name));
    }
}
