package com.omnixys.security.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PublicEndpointFilterTest {

    @Mock
    private HandlerMappingIntrospector handlerMappingIntrospector;

    @Mock
    private HandlerMapping handlerMapping;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private PublicEndpointFilter filter;

    @BeforeEach
    void setUp() {
        filter = new PublicEndpointFilter(handlerMappingIntrospector);
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldSetPublicTokenWhenMethodHasPublicAnnotation() throws Exception {
        Object handler = new PublicAnnotatedController();
        HandlerMethod handlerMethod = new HandlerMethod(handler, "publicEndpoint");
        HandlerExecutionChain chain = new HandlerExecutionChain(handlerMethod);
        when(handlerMappingIntrospector.getHandlerMappings()).thenReturn(List.of(handlerMapping));
        when(handlerMapping.getHandler(request)).thenReturn(chain);

        filter.doFilter(request, response, filterChain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_PUBLIC")));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldSetPublicTokenWhenClassHasPublicAnnotation() throws Exception {
        Object handler = new ClassLevelPublicController();
        HandlerMethod handlerMethod = new HandlerMethod(handler, "regularEndpoint");
        HandlerExecutionChain chain = new HandlerExecutionChain(handlerMethod);
        when(handlerMappingIntrospector.getHandlerMappings()).thenReturn(List.of(handlerMapping));
        when(handlerMapping.getHandler(request)).thenReturn(chain);

        filter.doFilter(request, response, filterChain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_PUBLIC")));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetAuthenticationWhenNoPublicAnnotation() throws Exception {
        Object handler = new NonPublicController();
        HandlerMethod handlerMethod = new HandlerMethod(handler, "securedEndpoint");
        HandlerExecutionChain chain = new HandlerExecutionChain(handlerMethod);
        when(handlerMappingIntrospector.getHandlerMappings()).thenReturn(List.of(handlerMapping));
        when(handlerMapping.getHandler(request)).thenReturn(chain);

        filter.doFilter(request, response, filterChain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNull(authentication);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldCallFilterChainWhenHandlerMappingReturnsNull() throws Exception {
        when(handlerMappingIntrospector.getHandlerMappings()).thenReturn(List.of(handlerMapping));
        when(handlerMapping.getHandler(request)).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldCallFilterChainWhenHandlerResolutionThrowsException() throws Exception {
        when(handlerMappingIntrospector.getHandlerMappings()).thenReturn(List.of(handlerMapping));
        when(handlerMapping.getHandler(request)).thenThrow(new RuntimeException("Handler resolution failed"));

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    static class PublicAnnotatedController {
        @Public
        public void publicEndpoint() {
        }
    }

    @Public
    static class ClassLevelPublicController {
        public void regularEndpoint() {
        }
    }

    static class NonPublicController {
        public void securedEndpoint() {
        }
    }
}
