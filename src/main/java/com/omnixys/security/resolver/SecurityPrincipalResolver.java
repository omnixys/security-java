package com.omnixys.security.resolver;

import com.omnixys.context.PrincipalContext;
import com.omnixys.context.resolver.PrincipalResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.stream.Collectors;

public class SecurityPrincipalResolver implements PrincipalResolver {

    @Override
    public PrincipalContext resolve(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }

        Jwt jwt = extractJwt(authentication);
        if (jwt == null) {
            return null;
        }

        String subject = jwt.getSubject();
        if (subject == null) {
            subject = jwt.getClaimAsString("preferred_username");
        }
        if (subject == null) {
            return null;
        }

        String actorId = jwt.getClaimAsString("actor_id");
        String userId = jwt.getClaimAsString("user_id");
        String tenantId = jwt.getClaimAsString("tenant_id");
        String sessionId = jwt.getClaimAsString("session_id");
        String authStrength = jwt.getClaimAsString("auth_strength");

        Number authTime = jwt.getClaim("auth_time");
        Long authenticatedAtEpochMs = authTime != null ? authTime.longValue() * 1000 : null;

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new PrincipalContext(subject, actorId, userId, tenantId, roles, sessionId, authStrength, authenticatedAtEpochMs);
    }

    private Jwt extractJwt(Authentication authentication) {
        if (authentication instanceof org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken jwtAuth) {
            return jwtAuth.getToken();
        }
        if (authentication instanceof com.omnixys.security.model.CustomAuthenticationToken customAuth) {
            return customAuth.getJwt();
        }
        if (authentication.getCredentials() instanceof Jwt jwt) {
            return jwt;
        }
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        return null;
    }
}
