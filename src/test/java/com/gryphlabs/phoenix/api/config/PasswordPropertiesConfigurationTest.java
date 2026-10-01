package com.gryphlabs.phoenix.api.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("local")
class PasswordPropertiesConfigurationTest {
    @Autowired PasswordProperties properties;

    @Test
    void bindsCompleteBasePasswordPolicy() {
        assertEquals(12, properties.minLength());
        assertEquals(1, properties.uppercase());
        assertEquals(1, properties.lowercase());
        assertEquals(1, properties.numbers());
        assertEquals(1, properties.special());
        assertEquals("!@#$%^&*()_+-=[]{}", properties.specialCharacters());
    }
}
