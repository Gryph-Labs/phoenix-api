package com.gryphlabs.phoenix.api;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("local")
@TestPropertySource(properties = {
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=63999"
})
class PhoenixStartupWithoutRedisTest {
    @Test
    void contextStartsWithoutRedis() {
        assertTrue(true);
    }
}
