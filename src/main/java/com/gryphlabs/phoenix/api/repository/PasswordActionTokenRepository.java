package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.PasswordActionToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.Optional;

public interface PasswordActionTokenRepository extends JpaRepository<PasswordActionToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<PasswordActionToken> findByTokenHash(String hash);
}
