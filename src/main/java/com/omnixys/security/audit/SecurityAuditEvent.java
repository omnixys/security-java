package com.omnixys.security.audit;

import java.util.Map;

public record SecurityAuditEvent(
        String type,
        String userId,
        String ip,
        String userAgent,
        long timestamp,
        String requestId,
        String correlationId,
        String traceId,
        String actorId,
        String tenantId,
        Map<String, Object> meta
) {
    public enum EventType {
        LOGIN, LOGOUT, TOKEN_REVOKED, ACCESS_DENIED
    }
}
