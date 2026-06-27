package com.omnixys.security.cookie;

import com.omnixys.security.config.SecurityProperties;

public class CookieService {

    private final SecurityProperties properties;

    public CookieService(SecurityProperties properties) {
        this.properties = properties;
    }

    public CookieDefaults getDefaults() {
        return new CookieDefaults(
                true,
                properties.getCookieSecure(),
                properties.getCookieSameSite(),
                properties.getCookieDomain(),
                properties.getCookiePath()
        );
    }

    public record CookieDefaults(
            boolean httpOnly,
            boolean secure,
            String sameSite,
            String domain,
            String path
    ) {}
}
