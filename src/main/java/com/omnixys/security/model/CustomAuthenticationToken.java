package com.omnixys.security.model;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

@Getter
public class CustomAuthenticationToken extends AbstractAuthenticationToken {
    private final UserDetails userDetails;
    private final Jwt jwt;

    public CustomAuthenticationToken(UserDetails userDetails, Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.userDetails = userDetails;
        this.jwt = jwt;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return jwt.getTokenValue();
    }

    @Override
    public Object getPrincipal() {
        return userDetails;
    }
}
