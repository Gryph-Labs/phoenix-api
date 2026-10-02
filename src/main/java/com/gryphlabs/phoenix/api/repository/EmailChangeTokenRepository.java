package com.gryphlabs.phoenix.api.repository;

import com.gryphlabs.phoenix.api.entity.EmailChangeToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface EmailChangeTokenRepository extends JpaRepository<EmailChangeToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<EmailChangeToken> findByTokenHash(String hash);

    @Modifying
    @Query("update EmailChangeToken t set t.consumed=true where t.user.id=:userId and t.consumed=false")
    int consumeForUser(Long userId);
}
