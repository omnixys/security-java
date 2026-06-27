package com.omnixys.security.audit;

import com.omnixys.context.ContextAccessor;
import com.omnixys.context.ContextSnapshot;

import java.time.Instant;
import java.util.function.BiConsumer;

public class SecurityAuditService {

    private final BiConsumer<String, SecurityAuditEvent> producer;

    public SecurityAuditService(BiConsumer<String, SecurityAuditEvent> producer) {
        this.producer = producer;
    }

    public void log(SecurityAuditEvent event) {
        ContextSnapshot context = ContextAccessor.get();
        SecurityAuditEvent enriched = new SecurityAuditEvent(
                event.type(),
                event.userId(),
                event.ip(),
                event.userAgent(),
                Instant.now().toEpochMilli(),
                event.requestId() != null ? event.requestId() :
                        (context != null ? context.requestId() : "unscoped"),
                event.correlationId() != null ? event.correlationId() :
                        (context != null ? (context.correlationId() != null ? context.correlationId() : context.requestId()) : "unscoped"),
                event.traceId() != null ? event.traceId() :
                        (context != null && context.trace() != null ? context.trace().traceId() : null),
                event.actorId() != null ? event.actorId() :
                        (context != null && context.principal() != null ? context.principal().actorId() : null),
                event.tenantId() != null ? event.tenantId() :
                        (context != null && context.tenant() != null ? context.tenant().tenantId() :
                                (context != null && context.principal() != null ? context.principal().tenantId() : null)),
                event.meta()
        );
        producer.accept("security.audit", enriched);
    }
}
