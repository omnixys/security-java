package com.omnixys.security.cookie;

import com.omnixys.security.config.SecurityProperties;

public class TokenCookieService {

    private final CookieService cookieService;
    private final SecurityProperties properties;

    public TokenCookieService(CookieService cookieService, SecurityProperties properties) {
        this.cookieService = cookieService;
        this.properties = properties;
    }

    public TokenCookieOptions accessTokenOptions() {
        return toOptions(properties.getAccessTokenName(), properties.getAccessTokenMaxAgeMs());
    }

    public TokenCookieOptions refreshTokenOptions() {
        return toOptions(properties.getRefreshTokenName(), properties.getRefreshTokenMaxAgeMs());
    }

    private TokenCookieOptions toOptions(String name, Long maxAgeMs) {
        CookieService.CookieDefaults defaults = cookieService.getDefaults();
        Integer maxAgeSec = maxAgeMs != null ? (int) Math.ceil(maxAgeMs / 1000.0) : null;
        return new TokenCookieOptions(name, defaults.httpOnly(), defaults.secure(),
                defaults.sameSite(), defaults.domain(), defaults.path(), maxAgeSec);
    }

    public record TokenCookieOptions(
            String name,
            boolean httpOnly,
            boolean secure,
            String sameSite,
            String domain,
            String path,
            Integer maxAge
    ) {}
}
