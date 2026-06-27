package com.omnixys.security.config;

import com.omnixys.security.auth.InternalGatewayFilter;
import com.omnixys.security.auth.PublicEndpointFilter;
import com.omnixys.security.model.JwtToUserDetailsConverter;
import com.omnixys.security.revocation.TokenRevocationFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder;

@Configuration
public class SecurityConfiguration {

    private final SecurityProperties properties;

    public SecurityConfiguration(SecurityProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtToUserDetailsConverter converter,
            PublicEndpointFilter publicEndpointFilter,
            TokenRevocationFilter tokenRevocationFilter,
            @Nullable InternalGatewayFilter internalGatewayFilter,
            CorsConfigurationSource corsConfigurationSource
    ) throws Exception {

        http.authorizeHttpRequests(auth -> {
            properties.getPermitAllPostPaths().forEach(path ->
                auth.requestMatchers(POST, path).permitAll()
            );
            properties.getPermitAllGetPaths().forEach(path ->
                auth.requestMatchers(GET, path).permitAll()
            );
            properties.getPermitAllPaths().forEach(path ->
                auth.requestMatchers(path).permitAll()
            );
            auth.anyRequest().authenticated();
        });

        http.addFilterBefore(publicEndpointFilter, AuthorizationFilter.class);

        http.addFilterAfter(tokenRevocationFilter, AuthorizationFilter.class);

        if (internalGatewayFilter != null) {
            http.addFilterBefore(internalGatewayFilter, BearerTokenAuthenticationFilter.class);
        }

        http.oauth2ResourceServer(oauth2 ->
            oauth2.jwt(jwt ->
                jwt.jwtAuthenticationConverter(converter)
            )
        );

        if (properties.isStateless()) {
            http.sessionManagement(session ->
                session.sessionCreationPolicy(STATELESS)
            );
        }

        if (properties.isFormLoginDisabled()) {
            http.formLogin(AbstractHttpConfigurer::disable);
        }
        if (properties.isCsrfDisabled()) {
            http.csrf(AbstractHttpConfigurer::disable);
        }

        http.cors(cors -> cors.configurationSource(corsConfigurationSource));

        http.headers(headers ->
            headers.frameOptions(FrameOptionsConfig::sameOrigin)
        );

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource() {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(properties.getCors().getAllowedOrigins());
        config.setAllowedMethods(properties.getCors().getAllowedMethods());
        config.setAllowedHeaders(properties.getCors().getAllowedHeaders());
        config.setAllowCredentials(properties.getCors().isAllowCredentials());
        config.setMaxAge(properties.getCors().getMaxAgeSeconds());

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return createDelegatingPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
