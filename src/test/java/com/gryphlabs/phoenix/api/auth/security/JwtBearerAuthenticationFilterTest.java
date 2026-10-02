package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.JwtService;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class JwtBearerAuthenticationFilterTest {
    private final JwtService jwt = new JwtService("01234567890123456789012345678901", Duration.ofMinutes(15), Clock.systemUTC());
    private final JwtBearerAuthenticationFilter filter = new JwtBearerAuthenticationFilter(jwt);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validBearerPopulatesPrincipalAndAuthorities() throws Exception {
        var u = new User();
        u.setId(7L);
        u.setRole(Role.USER);
        u.setStatus(UserStatus.ACTIVE);
        var req = new MockHttpServletRequest();
        req.addHeader("Authorization", "Bearer " + jwt.createAccessToken(u));
        var res = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);
        filter.doFilter(req, res, chain);
        assertEquals("7", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        verify(chain).doFilter(req, res);
        assertNull(req.getSession(false));
    }

    @Test
    void missingInvalidAndMalformedBearerReturnUnauthorized() throws Exception {
        for (String header : new String[]{null, "Basic abc", "Bearer bad"}) {
            SecurityContextHolder.clearContext();
            var req = new MockHttpServletRequest();
            if (header != null) {
                req.addHeader("Authorization", header);
            }
            var res = new MockHttpServletResponse();
            var chain = mock(FilterChain.class);
            filter.doFilter(req, res, chain);
            if (header != null) {
                assertEquals(401, res.getStatus());
            }
        }
    }
}
