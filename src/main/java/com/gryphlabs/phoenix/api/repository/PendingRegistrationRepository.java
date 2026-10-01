package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.PendingRegistration;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PendingRegistrationRepository extends JpaRepository<PendingRegistration, Long> {
    Optional<PendingRegistration> findByEmail(String normalizedEmail);

    Optional<PendingRegistration> findByTokenHash(String tokenHash);
}
