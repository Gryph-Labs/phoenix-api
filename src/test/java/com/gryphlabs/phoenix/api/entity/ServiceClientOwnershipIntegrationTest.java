package com.gryphlabs.phoenix.api.entity;

import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("local")
class ServiceClientOwnershipIntegrationTest {
    @Autowired
    UserRepository users;
    @Autowired
    ServiceClientRepository clients;

    @Test
    void ownershipIsRequiredAndOwnerStateDoesNotOwnCallerLifecycle() {
        var owner = new User();
        owner.setEmail("owner-" + System.nanoTime() + "@example.com");
        owner.setDisplayName("Owner");
        owner.setPassword("encoded");
        owner.setRole(Role.USER);
        owner.setStatus(UserStatus.ACTIVE);
        owner = users.saveAndFlush(owner);

        var caller = new ServiceClient();
        caller.setClientId("caller-" + System.nanoTime());
        caller.setClientSecretHash("hash");
        caller.setOwner(owner);
        caller = clients.saveAndFlush(caller);

        owner.setStatus(UserStatus.DISABLED);
        users.saveAndFlush(owner);
        assertTrue(clients.findById(caller.getId()).isPresent());
        owner.setStatus(UserStatus.ACTIVE);
        users.saveAndFlush(owner);
        caller.setRevoked(true);
        clients.saveAndFlush(caller);
        assertTrue(clients.findById(caller.getId()).orElseThrow().isRevoked());
        var ownerId = owner.getId();
        assertThrows(DataIntegrityViolationException.class, () -> users.deleteById(ownerId));
    }

    @Test
    void ownerRelationshipIsNonNullable() {
        var caller = new ServiceClient();
        caller.setClientId("no-owner-" + System.nanoTime());
        caller.setClientSecretHash("hash");
        assertThrows(DataIntegrityViolationException.class, () -> clients.saveAndFlush(caller));
    }
}
