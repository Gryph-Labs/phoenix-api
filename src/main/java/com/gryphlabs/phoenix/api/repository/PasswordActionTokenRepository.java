package com.gryphlabs.phoenix.api.repository;
import com.gryphlabs.phoenix.api.entity.PasswordActionToken;
import org.springframework.data.jpa.repository.*; import jakarta.persistence.LockModeType;
import java.util.Optional;
public interface PasswordActionTokenRepository extends JpaRepository<PasswordActionToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE) Optional<PasswordActionToken> findByTokenHash(String hash);
}
