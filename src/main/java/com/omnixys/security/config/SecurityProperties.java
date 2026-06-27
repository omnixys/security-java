package com.omnixys.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "omnixys.security")
public class SecurityProperties {

    private List<String> permitAllPostPaths = new ArrayList<>();
    private List<String> permitAllGetPaths = new ArrayList<>(List.of(
            "/v3/api-docs.yaml",
            "/v3/api-docs",
            "/graphiql"
    ));
    private List<String> permitAllPaths = new ArrayList<>(List.of(
            "/actuator/health/**",
            "/actuator/prometheus",
            "/error",
            "/error/**"
    ));
    private boolean stateless = true;
    private boolean formLoginDisabled = true;
    private boolean csrfDisabled = true;

    private JweConfig jwe = new JweConfig();
    private EncryptionConfig encryption = new EncryptionConfig();
    private HmacConfig hmac = new HmacConfig();
    private SessionConfig session = new SessionConfig();
    private RateLimitConfig rateLimit = new RateLimitConfig();
    private RevocationConfig revocation = new RevocationConfig();
    private CookieConfig cookie = new CookieConfig();

    public List<String> getPermitAllPostPaths() { return permitAllPostPaths; }
    public void setPermitAllPostPaths(List<String> permitAllPostPaths) { this.permitAllPostPaths = permitAllPostPaths; }
    public List<String> getPermitAllGetPaths() { return permitAllGetPaths; }
    public void setPermitAllGetPaths(List<String> permitAllGetPaths) { this.permitAllGetPaths = permitAllGetPaths; }
    public List<String> getPermitAllPaths() { return permitAllPaths; }
    public void setPermitAllPaths(List<String> permitAllPaths) { this.permitAllPaths = permitAllPaths; }
    public boolean isStateless() { return stateless; }
    public void setStateless(boolean stateless) { this.stateless = stateless; }
    public boolean isFormLoginDisabled() { return formLoginDisabled; }
    public void setFormLoginDisabled(boolean formLoginDisabled) { this.formLoginDisabled = formLoginDisabled; }
    public boolean isCsrfDisabled() { return csrfDisabled; }
    public void setCsrfDisabled(boolean csrfDisabled) { this.csrfDisabled = csrfDisabled; }
    public JweConfig getJwe() { return jwe; }
    public void setJwe(JweConfig jwe) { this.jwe = jwe; }
    public EncryptionConfig getEncryption() { return encryption; }
    public void setEncryption(EncryptionConfig encryption) { this.encryption = encryption; }
    public HmacConfig getHmac() { return hmac; }
    public void setHmac(HmacConfig hmac) { this.hmac = hmac; }
    public SessionConfig getSession() { return session; }
    public void setSession(SessionConfig session) { this.session = session; }
    public RateLimitConfig getRateLimit() { return rateLimit; }
    public void setRateLimit(RateLimitConfig rateLimit) { this.rateLimit = rateLimit; }
    public RevocationConfig getRevocation() { return revocation; }
    public void setRevocation(RevocationConfig revocation) { this.revocation = revocation; }
    public CookieConfig getCookie() { return cookie; }
    public void setCookie(CookieConfig cookie) { this.cookie = cookie; }

    public static class JweConfig {
        private List<String> keys = new ArrayList<>();
        public List<String> getKeys() { return keys; }
        public void setKeys(List<String> keys) { this.keys = keys; }
    }

    public static class EncryptionConfig {
        private String key;
        public String getKey() { return key; }
        public void setKey(String key) { this.key = key; }
    }

    public static class HmacConfig {
        private String resetTokenKey;
        private String deviceFingerprintKey;
        private String magicLinkKey;
        public String getResetTokenKey() { return resetTokenKey; }
        public void setResetTokenKey(String resetTokenKey) { this.resetTokenKey = resetTokenKey; }
        public String getDeviceFingerprintKey() { return deviceFingerprintKey; }
        public void setDeviceFingerprintKey(String deviceFingerprintKey) { this.deviceFingerprintKey = deviceFingerprintKey; }
        public String getMagicLinkKey() { return magicLinkKey; }
        public void setMagicLinkKey(String magicLinkKey) { this.magicLinkKey = magicLinkKey; }
    }

    public static class SessionConfig {
        private long ttlMs = 3600000;
        public long getTtlMs() { return ttlMs; }
        public void setTtlMs(long ttlMs) { this.ttlMs = ttlMs; }
    }

    public static class RateLimitConfig {
        private boolean enabled = true;
        private int defaultLimit = 100;
        private long defaultWindowMs = 60000;
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getDefaultLimit() { return defaultLimit; }
        public void setDefaultLimit(int defaultLimit) { this.defaultLimit = defaultLimit; }
        public long getDefaultWindowMs() { return defaultWindowMs; }
        public void setDefaultWindowMs(long defaultWindowMs) { this.defaultWindowMs = defaultWindowMs; }
    }

    public static class RevocationConfig {
        private boolean enabled = true;
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class CookieConfig {
        private boolean secure = true;
        private String sameSite = "none";
        private String domain;
        private String path = "/";
        private String accessTokenName = "access_token";
        private String refreshTokenName = "refresh_token";
        private Long accessTokenMaxAgeMs;
        private Long refreshTokenMaxAgeMs;
        public boolean isSecure() { return secure; }
        public void setSecure(boolean secure) { this.secure = secure; }
        public String getSameSite() { return sameSite; }
        public void setSameSite(String sameSite) { this.sameSite = sameSite; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getAccessTokenName() { return accessTokenName; }
        public void setAccessTokenName(String accessTokenName) { this.accessTokenName = accessTokenName; }
        public String getRefreshTokenName() { return refreshTokenName; }
        public void setRefreshTokenName(String refreshTokenName) { this.refreshTokenName = refreshTokenName; }
        public Long getAccessTokenMaxAgeMs() { return accessTokenMaxAgeMs; }
        public void setAccessTokenMaxAgeMs(Long accessTokenMaxAgeMs) { this.accessTokenMaxAgeMs = accessTokenMaxAgeMs; }
        public Long getRefreshTokenMaxAgeMs() { return refreshTokenMaxAgeMs; }
        public void setRefreshTokenMaxAgeMs(Long refreshTokenMaxAgeMs) { this.refreshTokenMaxAgeMs = refreshTokenMaxAgeMs; }
    }

    private InternalGatewayConfig internalGateway = new InternalGatewayConfig();
    private CorsConfig cors = new CorsConfig();

    public InternalGatewayConfig getInternalGateway() { return internalGateway; }
    public void setInternalGateway(InternalGatewayConfig internalGateway) { this.internalGateway = internalGateway; }
    public CorsConfig getCors() { return cors; }
    public void setCors(CorsConfig cors) { this.cors = cors; }

    public boolean getCookieSecure() { return cookie.secure; }
    public String getCookieSameSite() { return cookie.sameSite; }
    public String getCookieDomain() { return cookie.domain; }
    public String getCookiePath() { return cookie.path; }
    public String getAccessTokenName() { return cookie.accessTokenName; }
    public String getRefreshTokenName() { return cookie.refreshTokenName; }
    public Long getAccessTokenMaxAgeMs() { return cookie.accessTokenMaxAgeMs; }
    public Long getRefreshTokenMaxAgeMs() { return cookie.refreshTokenMaxAgeMs; }

    public static class InternalGatewayConfig {
        private String token;

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    public static class CorsConfig {
        private List<String> allowedOrigins = new ArrayList<>(List.of(
                "http://localhost:3000",
                "http://localhost:5173",
                "http://localhost:8080",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173",
                "http://127.0.0.1:8080"
        ));
        private List<String> allowedMethods = new ArrayList<>(List.of(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));
        private List<String> allowedHeaders = new ArrayList<>(List.of(
                "Authorization", "Content-Type", "X-Requested-With",
                "Accept", "Origin", "Cookie", "X-Correlation-Id",
                "X-Request-Id", "X-Trace-Id", "X-Tenant-Id"
        ));
        private boolean allowCredentials = true;
        private long maxAgeSeconds = 1800;

        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
        public List<String> getAllowedMethods() { return allowedMethods; }
        public void setAllowedMethods(List<String> allowedMethods) { this.allowedMethods = allowedMethods; }
        public List<String> getAllowedHeaders() { return allowedHeaders; }
        public void setAllowedHeaders(List<String> allowedHeaders) { this.allowedHeaders = allowedHeaders; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
        public long getMaxAgeSeconds() { return maxAgeSeconds; }
        public void setMaxAgeSeconds(long maxAgeSeconds) { this.maxAgeSeconds = maxAgeSeconds; }
    }
}
