package com.gryphlabs.phoenix.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "pending_registrations", uniqueConstraints = {
        @UniqueConstraint(name = "uk_pending_registration_email", columnNames = "email"),
        @UniqueConstraint(name = "uk_pending_registration_token_hash", columnNames = "token_hash")
})
@Getter
@Setter
@NoArgsConstructor
public class PendingRegistration extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @NotBlank
    @Column(nullable = false, length = 320)
    private String email;

    @NotBlank
    @Column(nullable = false)
    private String displayName;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(nullable = false)
    private Instant expiresAt;
}
