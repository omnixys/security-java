package com.omnixys.security.service;

import com.omnixys.security.enums.RoleType;
import com.omnixys.security.model.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtUserDetailsService {

    public UserDetails loadUserDetailsFromJwt(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            throw new IllegalArgumentException("JWT does not contain 'preferred_username' claim");
        }

        List<String> roles = extractRoles(jwt);

        Collection<GrantedAuthority> authorities = roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
            .collect(Collectors.toList());

        return new CustomUserDetails(username, authorities, jwt);
    }

    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("realm_access.roles");

        if (roles == null) {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> extractedRoles = (List<String>) realmAccess.get("roles");
                return extractedRoles != null
                    ? extractedRoles.stream()
                    .map(role -> role.replace(" ", "_").toUpperCase())
                    .filter(this::isValidRole)
                    .toList()
                    : new ArrayList<>();
            }
        }
        return roles != null
            ? roles.stream()
                .map(role -> role.replace(" ", "_").toUpperCase())
                .filter(this::isValidRole)
                .toList()
            : new ArrayList<>();
    }

    private boolean isValidRole(String role) {
        try {
            RoleType.valueOf(role);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
