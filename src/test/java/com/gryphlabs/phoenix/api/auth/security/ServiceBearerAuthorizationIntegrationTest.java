package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.CallerAuthorizationStateService;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
@Import(ServiceBearerAuthorizationIntegrationTest.TestRouteConfiguration.class)
class ServiceBearerAuthorizationIntegrationTest {
    @Autowired
    MockMvc mockMvc;
    @Autowired
    UserRepository users;
    @Autowired
    ServiceClientRepository clients;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    CallerAuthorizationStateService authorizationState;

    @Test
    void ownerAndCallerStateChangesApplyToTheSameUnexpiredBearerToken() throws Exception {
        var owner = new User();
        owner.setEmail("bearer-owner-" + System.nanoTime() + "@example.com");
        owner.setDisplayName("Bearer Owner");
        owner.setPassword("encoded");
        owner.setRole(Role.USER);
        owner.setStatus(UserStatus.ACTIVE);
        owner = users.saveAndFlush(owner);

        var client = new ServiceClient();
        client.setClientId("bearer-client-" + System.nanoTime());
        client.setClientSecretHash(passwordEncoder.encode("client-secret"));
        client.setOwner(owner);
        client = clients.saveAndFlush(client);

        var tokenRequest = "{\"grantType\":\"client_credentials\",\"clientId\":\"" + client.getClientId() + "\",\"clientSecret\":\"client-secret\"}";
        var token = mockMvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON).content(tokenRequest))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var tokenJson = com.fasterxml.jackson.databind.json.JsonMapper.builder().build().readTree(token);
        var jwt = tokenJson.get("accessToken").asText();
        org.junit.jupiter.api.Assertions.assertNull(tokenJson.get("refreshToken"));

        protectedCall(jwt, 200);
        owner.setStatus(UserStatus.DISABLED);
        users.saveAndFlush(owner);
        authorizationState.invalidateUser(owner.getId());
        protectedCall(jwt, 401);
        mockMvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON).content(tokenRequest)).andExpect(status().isUnauthorized());

        owner.setStatus(UserStatus.ACTIVE);
        users.saveAndFlush(owner);
        authorizationState.invalidateUser(owner.getId());
        protectedCall(jwt, 200);

        client.setEnabled(false);
        clients.saveAndFlush(client);
        authorizationState.invalidateCaller(client.getId());
        protectedCall(jwt, 401);
        mockMvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON).content(tokenRequest)).andExpect(status().isUnauthorized());

        client.setEnabled(true);
        clients.saveAndFlush(client);
        authorizationState.invalidateCaller(client.getId());
        protectedCall(jwt, 200);

        client.setRevoked(true);
        clients.saveAndFlush(client);
        authorizationState.invalidateCaller(client.getId());
        protectedCall(jwt, 401);
        mockMvc.perform(post("/auth/token").contentType(MediaType.APPLICATION_JSON).content(tokenRequest)).andExpect(status().isUnauthorized());

        owner.setStatus(UserStatus.DISABLED);
        users.saveAndFlush(owner);
        authorizationState.invalidateUser(owner.getId());
        owner.setStatus(UserStatus.ACTIVE);
        users.saveAndFlush(owner);
        authorizationState.invalidateUser(owner.getId());
        protectedCall(jwt, 401);
        assertTrue(client.isRevoked());
    }

    private void protectedCall(String jwt, int expectedStatus) throws Exception {
        mockMvc.perform(get("/test/protected").header("Authorization", "Bearer " + jwt))
                .andExpect(status().is(expectedStatus));
    }

    @TestConfiguration
    static class TestRouteConfiguration {
        @Bean
        TestProtectedController testProtectedController() {
            return new TestProtectedController();
        }
    }

    @RestController
    static class TestProtectedController {
        @GetMapping("/test/protected")
        String protectedRoute() {
            return "ok";
        }
    }
}
