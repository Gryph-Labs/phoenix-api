package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, Long> {
    Optional<ServiceClient> findByClientId(String clientId);

    @EntityGraph(attributePaths = "owner")
    Optional<ServiceClient> findWithOwnerById(Long id);

    List<ServiceClient> findByOwnerId(Long ownerId);
}
