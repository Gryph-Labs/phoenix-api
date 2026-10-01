package com.gryphlabs.phoenix.api.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

@Configuration
public class AuthenticationConfig {
    @Value("${app.security.password.encoder.strength}")
    private int passwordEncoderStrength;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(passwordEncoderStrength);
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
