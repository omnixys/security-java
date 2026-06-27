package com.omnixys.security.revocation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenRevocationFilterTest {

    @Mock private TokenRevocationService revocationService;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain chain;
    @Mock private Authentication auth;

    private TokenRevocationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TokenRevocationFilter(revocationService);
    }

    @Test
    void shouldPassWhenNoAuth() throws Exception {
        SecurityContextHolder.clearContext();
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldPassWhenNotAuthenticated() throws Exception {
        when(auth.isAuthenticated()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(auth);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldPassWhenCredentialsNotJwt() throws Exception {
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getCredentials()).thenReturn("not-a-jwt");
        SecurityContextHolder.getContext().setAuthentication(auth);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldPassWhenJtiIsNull() throws Exception {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getId()).thenReturn(null);
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getCredentials()).thenReturn(jwt);
        SecurityContextHolder.getContext().setAuthentication(auth);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldPassWhenJtiNotRevoked() throws Exception {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getId()).thenReturn("valid-jti");
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getCredentials()).thenReturn(jwt);
        when(revocationService.isRevoked("valid-jti")).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(auth);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldThrowWhenJtiRevoked() throws Exception {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getId()).thenReturn("revoked-jti");
        when(auth.isAuthenticated()).thenReturn(true);
        when(auth.getCredentials()).thenReturn(jwt);
        when(revocationService.isRevoked("revoked-jti")).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThrows(com.omnixys.commons.error.BaseOmnixysException.class,
                () -> filter.doFilterInternal(request, response, chain));
        verify(chain, never()).doFilter(any(), any());
    }
}
