package com.gryphlabs.phoenix.api.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "service_clients", indexes = @Index(name = "ix_service_client_client_id", columnList = "client_id", unique = true))
@Getter @Setter @NoArgsConstructor
public class ServiceClient {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "client_id", nullable = false, unique = true, updatable = false)
    private String clientId;
    @Column(name = "client_secret_hash", nullable = false)
    private String clientSecretHash;
    @Column(nullable = false)
    private boolean enabled = true;
    @Column(nullable = false)
    private boolean revoked = false;
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "service_client_authorities", joinColumns = @JoinColumn(name = "service_client_id"))
    @Column(name = "authority", nullable = false)
    private Set<String> authorities = new HashSet<>();
}
