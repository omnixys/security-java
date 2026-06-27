package com.omnixys.security.revocation;

import com.omnixys.commons.error.BaseOmnixysException;
import com.omnixys.commons.error.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenRevocationFilter extends OncePerRequestFilter {

    private final TokenRevocationService tokenRevocationService;

    public TokenRevocationFilter(TokenRevocationService tokenRevocationService) {
        this.tokenRevocationService = tokenRevocationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getCredentials() instanceof Jwt jwt) {
            String jti = jwt.getId();
            if (jti != null && tokenRevocationService.isRevoked(jti)) {
                throw new BaseOmnixysException(ErrorCode.TOKEN_REVOKED,
                        "Token has been revoked");
            }
        }
        chain.doFilter(request, response);
    }
}
