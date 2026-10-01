package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.JwtService;
import com.gryphlabs.phoenix.api.entity.*;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtBearerAuthenticationFilterTest {
    private final JwtService jwt = new JwtService("01234567890123456789012345678901", Duration.ofMinutes(15), Clock.systemUTC());
    private final JwtBearerAuthenticationFilter filter = new JwtBearerAuthenticationFilter(jwt);
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }
    @Test void validBearerPopulatesPrincipalAndAuthorities() throws Exception {
        var u = new User(); u.setId(7L); u.setRole(Role.USER); u.setStatus(UserStatus.ACTIVE);
        var req = new MockHttpServletRequest(); req.addHeader("Authorization", "Bearer " + jwt.createAccessToken(u));
        var res = new MockHttpServletResponse(); var chain = mock(FilterChain.class);
        filter.doFilter(req, res, chain);
        assertEquals("7", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        verify(chain).doFilter(req, res); assertNull(req.getSession(false));
    }
    @Test void missingInvalidAndMalformedBearerReturnUnauthorized() throws Exception {
        for (String header : new String[]{null, "Basic abc", "Bearer bad"}) {
            SecurityContextHolder.clearContext(); var req = new MockHttpServletRequest();
            if (header != null) {
                req.addHeader("Authorization", header);
            }
            var res = new MockHttpServletResponse(); var chain = mock(FilterChain.class); filter.doFilter(req, res, chain);
            if (header != null) {
                assertEquals(401, res.getStatus());
            }
        }
    }
}
