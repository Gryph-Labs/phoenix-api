package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.ServiceClient;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ServiceClientRepository extends JpaRepository<ServiceClient, Long> {
    Optional<ServiceClient> findByClientId(String clientId);
}
