package com.omnixys.security.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.omnixys.security.jwe.JweService;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public class SecureSessionService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JweService jweService;
    private final long defaultTtlMs;

    public SecureSessionService(JweService jweService, long defaultTtlMs) {
        this.jweService = jweService;
        this.defaultTtlMs = defaultTtlMs;
    }

    public String issue(Map<String, Object> payload, SessionIssueOptions options) {
        long now = Instant.now().toEpochMilli();
        long ttl = options.ttlMs() > 0 ? options.ttlMs() : defaultTtlMs;
        String sid = options.sessionId() != null ? options.sessionId() : UUID.randomUUID().toString();
        long authAt = options.authenticatedAtEpochMs() > 0 ? options.authenticatedAtEpochMs() : now;

        try {
            Map<String, Object> claims = new java.util.LinkedHashMap<>(payload);
            claims.put("sid", sid);
            claims.put("iat", now);
            claims.put("exp", now + ttl);
            claims.put("authenticatedAtEpochMs", authAt);
            if (options.authStrength() != null) {
                claims.put("authStrength", options.authStrength());
            }
            String json = MAPPER.writeValueAsString(claims);
            return jweService.encrypt(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to issue secure session", e);
        }
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> read(String token) {
        String json = jweService.decrypt(token);
        try {
            Map<String, Object> data = MAPPER.readValue(json, Map.class);
            Object expObj = data.get("exp");
            if (expObj instanceof Number exp && exp.longValue() < Instant.now().toEpochMilli()) {
                throw new RuntimeException("Session has expired");
            }
            return data;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to read secure session", e);
        }
    }

    public SessionMetadata metadata(String token) {
        Map<String, Object> data = read(token);
        Object sid = data.get("sid");
        Object iat = data.get("iat");
        Object exp = data.get("exp");
        Object authAt = data.get("authenticatedAtEpochMs");
        Object authStrength = data.get("authStrength");

        if (!(sid instanceof String) || !(iat instanceof Number) || !(exp instanceof Number)) {
            throw new RuntimeException("Invalid session metadata");
        }
        return new SessionMetadata(
                (String) sid,
                ((Number) iat).longValue(),
                ((Number) exp).longValue(),
                authAt instanceof Number ? ((Number) authAt).longValue() : ((Number) iat).longValue(),
                authStrength instanceof String ? (String) authStrength : null
        );
    }

    public record SessionIssueOptions(
            String sessionId,
            long ttlMs,
            long authenticatedAtEpochMs,
            String authStrength
    ) {
        public SessionIssueOptions() {
            this(null, 0, 0, null);
        }
    }

    public record SessionMetadata(
            String sessionId,
            long issuedAtEpochMs,
            long expiresAtEpochMs,
            long authenticatedAtEpochMs,
            String authStrength
    ) {}
}
