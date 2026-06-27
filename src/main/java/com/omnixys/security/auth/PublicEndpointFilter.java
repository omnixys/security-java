package com.omnixys.security.auth;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public class PublicEndpointFilter implements Filter {

    private static final AnonymousAuthenticationToken PUBLIC_TOKEN =
            new AnonymousAuthenticationToken(
                    UUID.randomUUID().toString(),
                    "public",
                    List.of(new SimpleGrantedAuthority("ROLE_PUBLIC"))
            );

    private final HandlerMappingIntrospector handlerMappingIntrospector;

    public PublicEndpointFilter(HandlerMappingIntrospector handlerMappingIntrospector) {
        this.handlerMappingIntrospector = handlerMappingIntrospector;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest httpRequest) {
            try {
                HandlerExecutionChain executionChain = resolveHandler(httpRequest);
                if (executionChain != null) {
                    Object handler = executionChain.getHandler();
                    if (handler instanceof HandlerMethod handlerMethod) {
                        if (hasPublicAnnotation(handlerMethod)) {
                            SecurityContextHolder.getContext().setAuthentication(PUBLIC_TOKEN);
                        }
                    }
                }
            } catch (Exception e) {
                // Handler resolution failure is non-fatal
            }
        }
        chain.doFilter(request, response);
    }

    private HandlerExecutionChain resolveHandler(HttpServletRequest request) {
        for (HandlerMapping hm : handlerMappingIntrospector.getHandlerMappings()) {
            try {
                HandlerExecutionChain chain = hm.getHandler(request);
                if (chain != null) return chain;
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private boolean hasPublicAnnotation(HandlerMethod handlerMethod) {
        if (handlerMethod.getMethodAnnotation(Public.class) != null) {
            return true;
        }
        if (handlerMethod.getBeanType().isAnnotationPresent(Public.class)) {
            return true;
        }
        return false;
    }
}
