package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.AuthenticationService;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.LoginRequest;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
class LogoutIntegrationTest {
    @Autowired
    MockMvc mockMvc;
    @Autowired
    AuthenticationService authenticationService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void logoutRevokesTokenWithoutAccessJwt() throws Exception {
        var user = new User();
        user.setEmail("logout-integration@example.com");
        user.setDisplayName("Logout Integration");
        user.setPassword(passwordEncoder.encode("Password1"));
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        var token = authenticationService.login(
                new LoginRequest("logout-integration@example.com", "Password1")).getRefreshToken();
        var body = "{\"refreshToken\":\"" + token + "\"}";

        mockMvc.perform(post("/auth/logout").contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());
        mockMvc.perform(post("/auth/refresh").contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownLogoutTokenRemainsSafeAndGeneric() throws Exception {
        var body = "{\"refreshToken\":\"unknown-token\"}";

        mockMvc.perform(post("/auth/logout").contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());
    }
}
