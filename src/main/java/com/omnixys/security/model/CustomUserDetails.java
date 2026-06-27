package com.omnixys.security.model;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

@Getter
public class CustomUserDetails implements UserDetails {
    private final String username;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Jwt jwt;

    public CustomUserDetails(String username, Collection<? extends GrantedAuthority> authorities, final Jwt jwt) {
        this.username = username;
        this.authorities = authorities;
        this.jwt = jwt;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getToken() {
        return jwt.getTokenValue();
    }
}
