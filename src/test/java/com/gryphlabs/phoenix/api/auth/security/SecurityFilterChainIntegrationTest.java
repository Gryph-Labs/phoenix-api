package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.JwtService;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import com.gryphlabs.phoenix.api.repository.UserRepository;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
class SecurityFilterChainIntegrationTest {
    @Autowired MockMvc mockMvc;
    @Autowired JwtService jwtService;
    @Autowired UserRepository userRepository;
    @Autowired ApplicationContext applicationContext;

    @Test
    void doesNotCreateSpringBootGeneratedUserDetailsService() {
        assertFalse(applicationContext.getBeansOfType(org.springframework.security.core.userdetails.UserDetailsService.class).values()
                .stream().anyMatch(service -> service.getClass().getName().contains("InMemoryUserDetailsManager")));
    }

    @Test
    void loginIsPublicWhileProtectedEndpointRequiresValidBearerToken() throws Exception {
        mockMvc.perform(get("/api/status"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/auth/password/change-request"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/password/change-request")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());

        var user = new User();
        user.setEmail("security@example.com"); user.setDisplayName("Security"); user.setPassword("encoded");
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        user = userRepository.save(user);
        var accessToken = jwtService.createAccessToken(user);

        mockMvc.perform(post("/auth/password/change-request")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(result -> assertNotEquals(401, result.getResponse().getStatus()));
    }
}
