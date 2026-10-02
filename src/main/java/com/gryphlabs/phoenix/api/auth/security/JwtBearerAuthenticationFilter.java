package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.AuthMetrics;
import com.gryphlabs.phoenix.api.auth.service.CallerAuthorizationStateService;
import com.gryphlabs.phoenix.api.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtBearerAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CallerAuthorizationStateService callerAuthorizationStateService;
    private final AuthMetrics metrics;

    @Autowired
    public JwtBearerAuthenticationFilter(JwtService jwtService, CallerAuthorizationStateService callerAuthorizationStateService, AuthMetrics metrics) {
        this.jwtService = jwtService;
        this.callerAuthorizationStateService = callerAuthorizationStateService;
        this.metrics = metrics;
    }

    public JwtBearerAuthenticationFilter(JwtService jwtService) {
        this(jwtService, null, null);
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws ServletException, IOException {
        var header = request.getHeader("Authorization");
        if (header != null) {
            if (!header.startsWith("Bearer ") || header.length() == 7) {
                response.sendError(401);
                return;
            }
            try {
                Claims claims = jwtService.parseAndValidate(header.substring(7));
                var actor = claims.get("actor", String.class);
                if (!"user".equals(actor) && !"service".equals(actor)) {
                    metrics.count("authorization.denied", "invalid_token");
                    response.sendError(401);
                    return;
                }
                var authorities = ((List<?>) claims.get("authorities", List.class)).stream()
                        .map(value -> new SimpleGrantedAuthority(String.valueOf(value))).toList();
                var auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), actor, authorities);
                if ("service".equals(actor)) {
                    var ownerId = claims.get("ownerId", String.class);
                    var state = ownerId == null || callerAuthorizationStateService == null
                            ? null : callerAuthorizationStateService.resolve(Long.parseLong(claims.getSubject()));
                    if (state == null || !state.allowed()) {
                        if (metrics != null) {
                            metrics.count("authorization.denied", "caller_not_authorized");
                        }
                        response.sendError(401);
                        return;
                    }
                    authorities = state.authorities().stream().map(SimpleGrantedAuthority::new).toList();
                    auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), actor, authorities);
                    if (metrics != null) {
                        metrics.count("authorization.allowed");
                    }
                }
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ex) {
                if (metrics != null) {
                    metrics.count("authorization.denied", "invalid_token");
                }
                response.sendError(401);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
