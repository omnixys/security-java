package com.omnixys.security.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

public class InternalGatewayAuthenticationToken extends AbstractAuthenticationToken {

    private static final String ROLE_INTERNAL_GATEWAY = "ROLE_INTERNAL_GATEWAY";

    public InternalGatewayAuthenticationToken() {
        super(List.of(new SimpleGrantedAuthority(ROLE_INTERNAL_GATEWAY)));
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return "internal-gateway";
    }
}
