package com.omnixys.security.resolver;

import com.omnixys.context.PrincipalContext;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityPrincipalResolverTest {

    @Mock
    private HttpServletRequest request;

    private SecurityPrincipalResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new SecurityPrincipalResolver();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldResolvePrincipalFromJwtAuthenticationToken() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("user123")
                .claim("preferred_username", "jdoe")
                .claim("actor_id", "actor-1")
                .claim("user_id", "user-1")
                .claim("tenant_id", "tenant-1")
                .claim("session_id", "sess-1")
                .claim("auth_strength", "phish-resistant")
                .claim("auth_time", 1700000000L)
                .build();

        Authentication authentication = new JwtAuthenticationToken(jwt, List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("SCOPE_read")
        ));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        PrincipalContext result = resolver.resolve(request);

        assertNotNull(result);
        assertEquals("user123", result.subject());
        assertEquals("actor-1", result.actorId());
        assertEquals("user-1", result.userId());
        assertEquals("tenant-1", result.tenantId());
        assertEquals("sess-1", result.sessionId());
        assertEquals("phish-resistant", result.authStrength());
        assertEquals(1700000000000L, result.authenticatedAtEpochMs());
        assertEquals(2, result.roles().size());
    }

    @Test
    void shouldReturnNullWhenAuthenticationIsNull() {
        SecurityContextHolder.getContext().setAuthentication(null);

        PrincipalContext result = resolver.resolve(request);

        assertNull(result);
    }

    @Test
    void shouldReturnNullWhenNotAuthenticated() {
        Authentication authentication = org.mockito.Mockito.mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        PrincipalContext result = resolver.resolve(request);

        assertNull(result);
    }

    @Test
    void shouldFallBackToPreferredUsernameWhenSubjectIsNull() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("preferred_username", "jdoe")
                .build();

        Authentication authentication = new JwtAuthenticationToken(jwt, List.of());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        PrincipalContext result = resolver.resolve(request);

        assertNotNull(result);
        assertEquals("jdoe", result.subject());
    }

    @Test
    void shouldReturnNullWhenBothSubjectAndPreferredUsernameAreNull() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("some_claim", "value")
                .build();

        Authentication authentication = new JwtAuthenticationToken(jwt, List.of());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        PrincipalContext result = resolver.resolve(request);

        assertNull(result);
    }

    @Test
    void shouldReturnNullWhenAuthenticationHasNoJwt() {
        Authentication authentication = org.mockito.Mockito.mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        PrincipalContext result = resolver.resolve(request);

        assertNull(result);
    }
}
