package com.omnixys.security.autoconfigure;

import com.omnixys.commons.error.BaseOmnixysException;
import com.omnixys.commons.error.ExceptionContext;
import com.omnixys.commons.util.StringUtils;
import com.omnixys.context.ContextAccessor;
import com.omnixys.context.ContextSnapshot;
import com.omnixys.context.resolver.PrincipalResolver;
import com.omnixys.security.audit.SecurityAuditService;
import com.omnixys.security.config.SecurityConfiguration;
import com.omnixys.security.config.SecurityProperties;
import com.omnixys.security.context.SecurityContextFilter;
import com.omnixys.security.cookie.CookieService;
import com.omnixys.security.cookie.TokenCookieService;
import com.omnixys.security.hash.EncryptionService;
import com.omnixys.security.hash.HashService;
import com.omnixys.security.hash.HmacService;
import com.omnixys.security.jwe.JweService;
import com.omnixys.security.model.JwtToUserDetailsConverter;
import com.omnixys.security.rateLimit.RateLimitService;
import com.omnixys.security.resolver.SecurityPrincipalResolver;
import com.omnixys.security.revocation.TokenRevocationFilter;
import com.omnixys.security.revocation.TokenRevocationService;
import com.omnixys.security.service.JwtUserDetailsService;
import com.omnixys.security.session.SecureSessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.StringRedisTemplate;
import com.omnixys.security.auth.InternalGatewayFilter;
import com.omnixys.security.auth.PublicEndpointFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnProperty(prefix = "omnixys.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import(SecurityConfiguration.class)
public class SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtUserDetailsService jwtUserDetailsService() {
        return new JwtUserDetailsService();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtToUserDetailsConverter jwtToUserDetailsConverter(JwtUserDetailsService service) {
        return new JwtToUserDetailsConverter(service);
    }

    @Bean
    @ConditionalOnMissingBean
    public PrincipalResolver securityPrincipalResolver() {
        return new SecurityPrincipalResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public PublicEndpointFilter publicEndpointFilter(HandlerMappingIntrospector handlerMappingIntrospector) {
        return new PublicEndpointFilter(handlerMappingIntrospector);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("omnixys.security.internal-gateway.token")
    public InternalGatewayFilter internalGatewayFilter(SecurityProperties properties) {
        return new InternalGatewayFilter(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextFilter securityContextFilter(PrincipalResolver resolver) {
        return new SecurityContextFilter(resolver);
    }

    @Bean
    public FilterRegistrationBean<SecurityContextFilter> securityContextFilterRegistration(SecurityContextFilter filter) {
        FilterRegistrationBean<SecurityContextFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.setOrder(Ordered.LOWEST_PRECEDENCE - 100);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAuditService securityAuditService() {
        Logger log = LoggerFactory.getLogger("security.audit");
        return new SecurityAuditService((topic, event) -> log.info("{}: type={} userId={} ip={}",
                topic, event.type(), StringUtils.mask(event.userId(), 4), StringUtils.mask(event.ip(), 0)));
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("omnixys.security.jwe.keys[0]")
    public JweService jweService(SecurityProperties properties) {
        List<byte[]> keys = properties.getJwe().getKeys().stream()
                .map(k -> Base64.getDecoder().decode(k))
                .toList();
        return new JweService(keys);
    }

    @Bean
    @ConditionalOnMissingBean
    public HashService hashService() {
        return new HashService();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("omnixys.security.encryption.key")
    public EncryptionService encryptionService(SecurityProperties properties) {
        byte[] key = Base64.getDecoder().decode(properties.getEncryption().getKey());
        return new EncryptionService(key);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("omnixys.security.hmac.reset-token-key")
    public HmacService hmacService(SecurityProperties properties) {
        byte[] resetTokenKey = properties.getHmac().getResetTokenKey().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] deviceFingerprintKey = properties.getHmac().getDeviceFingerprintKey() != null
                ? properties.getHmac().getDeviceFingerprintKey().getBytes(java.nio.charset.StandardCharsets.UTF_8) : null;
        byte[] magicLinkKey = properties.getHmac().getMagicLinkKey() != null
                ? properties.getHmac().getMagicLinkKey().getBytes(java.nio.charset.StandardCharsets.UTF_8) : null;
        return new HmacService(resetTokenKey, deviceFingerprintKey, magicLinkKey);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("omnixys.security.jwe.keys[0]")
    public SecureSessionService secureSessionService(JweService jweService, SecurityProperties properties) {
        return new SecureSessionService(jweService, properties.getSession().getTtlMs());
    }

    @Bean
    @ConditionalOnMissingBean
    public CookieService cookieService(SecurityProperties properties) {
        return new CookieService(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenCookieService tokenCookieService(CookieService cookieService, SecurityProperties properties) {
        return new TokenCookieService(cookieService, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "omnixys.security.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnClass(StringRedisTemplate.class)
    public RateLimitService.RateLimitStore rateLimitStore(StringRedisTemplate redis) {
        return new RedisRateLimitStore(redis);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "omnixys.security.rate-limit", name = "enabled", havingValue = "true", matchIfMissing = true)
    public RateLimitService rateLimitService(RateLimitService.RateLimitStore store, SecurityProperties properties) {
        return new RateLimitService(store,
                properties.getRateLimit().getDefaultLimit(),
                properties.getRateLimit().getDefaultWindowMs());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "omnixys.security.revocation", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnClass(StringRedisTemplate.class)
    public TokenRevocationService.RevocationStore revocationStore(StringRedisTemplate redis) {
        return new RedisRevocationStore(redis);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "omnixys.security.revocation", name = "enabled", havingValue = "true", matchIfMissing = true)
    public TokenRevocationService tokenRevocationService(TokenRevocationService.RevocationStore store) {
        return new TokenRevocationService(store);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "omnixys.security.revocation", name = "enabled", havingValue = "true", matchIfMissing = true)
    public TokenRevocationFilter tokenRevocationFilter(TokenRevocationService tokenRevocationService) {
        return new TokenRevocationFilter(tokenRevocationService);
    }

    @Bean
    public BaseOmnixysException.ContextProvider exceptionContextProvider() {
        BaseOmnixysException.ContextProvider provider = () -> {
            ContextSnapshot snapshot = ContextAccessor.get();
            if (snapshot == null) return null;
            return new ExceptionContext() {
                @Override public String requestId() { return snapshot.requestId(); }
                @Override public String correlationId() { return snapshot.correlationId(); }
                @Override public String traceId() { return snapshot.trace() != null ? snapshot.trace().traceId() : null; }
                @Override public String actorId() { return snapshot.principal() != null ? snapshot.principal().actorId() : null; }
                @Override public String tenantId() { return snapshot.tenant() != null ? snapshot.tenant().tenantId() : null; }
                @Override public Map<String, Object> metadata() { return Map.of(); }
            };
        };
        BaseOmnixysException.registerContextProvider(provider);
        return provider;
    }
}
