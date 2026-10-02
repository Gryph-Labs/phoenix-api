package com.gryphlabs.phoenix.api.auth.service;

import com.gryphlabs.phoenix.api.auth.mapper.MessageMapper;
import com.gryphlabs.phoenix.api.auth.mapper.TokenMapper;
import com.gryphlabs.phoenix.api.auth.validation.PasswordValidator;
import com.gryphlabs.phoenix.api.entity.ServiceClient;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import com.gryphlabs.phoenix.api.generated.auth.model.ServiceTokenRequest;
import com.gryphlabs.phoenix.api.repository.ServiceClientRepository;
import com.gryphlabs.phoenix.api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceServiceTokenTest {
    @Spy
    TokenMapper tokenMapper = new TokenMapper();
    @Spy
    MessageMapper messageMapper = new MessageMapper();
    @Mock
    CredentialService credentials;
    @Mock
    UserRepository users;
    @Mock
    PendingRegistrationService pending;
    @Mock
    EmailDeliveryService mail;
    @Mock
    PasswordValidator validator;
    @Mock
    PasswordEncoder encoder;
    @Mock
    JwtService jwt;
    @Mock
    RefreshTokenService refresh;
    @Mock
    ServiceClientRepository clients;
    @Mock
    AuthMetrics metrics;
    @InjectMocks
    AuthenticationService service;

    @Test
    void validClientCredentialsIssueServiceAccessToken() {
        var client = client(17L);
        when(clients.findByClientId("orders")).thenReturn(Optional.of(client));
        when(encoder.matches("secret", "hash")).thenReturn(true);
        when(jwt.createAccessToken(client)).thenReturn("jwt");
        when(jwt.serviceAccessLifetime()).thenReturn(Duration.ofHours(1));
        var response = service.issueServiceToken(request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "orders", "secret"));
        assertEquals("jwt", response.getAccessToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(3600L, response.getExpiresIn());
        verify(encoder).matches("secret", "hash");
        verify(metrics).count("service_token.request");
        verify(metrics).count("service_token.success");
        verify(metrics).stop(any(), eq("service_token.issuance_latency"));
    }

    @Test
    void unknownWrongDisabledRevokedAndUnsupportedAreGenericFailures() {
        var request = request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "missing", "bad");
        when(clients.findByClientId("missing")).thenReturn(Optional.empty());
        var unknown = assertThrows(BadCredentialsException.class, () -> service.issueServiceToken(request));
        var client = client(17L);
        when(clients.findByClientId("orders")).thenReturn(Optional.of(client));
        when(encoder.matches("bad", "hash")).thenReturn(false);
        var wrong = assertThrows(BadCredentialsException.class, () -> service.issueServiceToken(request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "orders", "bad")));
        client.setEnabled(false);
        var disabled = assertThrows(BadCredentialsException.class, () -> service.issueServiceToken(request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "orders", "bad")));
        client.setEnabled(true);
        client.setRevoked(true);
        var revoked = assertThrows(BadCredentialsException.class, () -> service.issueServiceToken(request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "orders", "bad")));
        var unsupported = assertThrows(BadCredentialsException.class, () -> service.issueServiceToken(request(null, "orders", "bad")));
        assertEquals(unknown.getMessage(), wrong.getMessage());
        assertEquals(wrong.getMessage(), disabled.getMessage());
        assertEquals(disabled.getMessage(), revoked.getMessage());
        assertEquals(revoked.getMessage(), unsupported.getMessage());
    }

    @Test
    void storedSecretIsVerifiedByPasswordEncoderAndClientsAreIndependent() {
        var first = client(1L);
        var second = client(2L);
        second.setClientId("two");
        assertNotEquals("secret", first.getClientSecretHash());
        when(clients.findByClientId("one")).thenReturn(Optional.of(first));
        when(encoder.matches("secret", "hash")).thenReturn(true);
        when(jwt.createAccessToken(first)).thenReturn("jwt");
        when(jwt.serviceAccessLifetime()).thenReturn(Duration.ZERO);
        service.issueServiceToken(request(ServiceTokenRequest.GrantTypeEnum.CLIENT_CREDENTIALS, "one", "secret"));
        first.setRevoked(true);
        assertFalse(second.isRevoked());
        verify(encoder).matches("secret", "hash");
    }

    private ServiceClient client(long id) {
        var c = new ServiceClient();
        c.setId(id);
        c.setClientId(id == 1 ? "one" : "orders");
        c.setClientSecretHash("hash");
        c.setAuthorities(new HashSet<>(Set.of("ROLE_SERVICE")));
        var owner = new User();
        owner.setId(99L);
        owner.setStatus(UserStatus.ACTIVE);
        c.setOwner(owner);
        return c;
    }

    private ServiceTokenRequest request(ServiceTokenRequest.GrantTypeEnum grant, String id, String secret) {
        return new ServiceTokenRequest(grant, id, secret);
    }
}
