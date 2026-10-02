package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, Long> {
    Optional<ServiceClient> findByClientId(String clientId);

    @Query("select client from ServiceClient client join fetch client.owner where client.id = :id")
    Optional<ServiceClient> findWithOwnerById(@Param("id") Long id);

    List<ServiceClient> findByOwnerId(Long ownerId);
}
