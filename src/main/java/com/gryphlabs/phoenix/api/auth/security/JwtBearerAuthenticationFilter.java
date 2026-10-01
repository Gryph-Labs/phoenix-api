package com.gryphlabs.phoenix.api.auth.security;

import com.gryphlabs.phoenix.api.auth.service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
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

    public JwtBearerAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
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
                    response.sendError(401);
                    return;
                }
                var authorities = ((List<?>) claims.get("authorities", List.class)).stream()
                        .map(value -> new SimpleGrantedAuthority(String.valueOf(value))).toList();
                var auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), actor, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ex) {
                response.sendError(401);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
