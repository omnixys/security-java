package com.omnixys.security.context;

import com.omnixys.context.ContextAccessor;
import com.omnixys.context.ContextSnapshot;
import com.omnixys.context.PrincipalContext;
import com.omnixys.context.resolver.PrincipalResolver;
import com.omnixys.observability.tracing.SpanEnricher;
import io.opentelemetry.api.trace.Span;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;

import java.io.IOException;

public class SecurityContextFilter implements Filter {

    private final PrincipalResolver principalResolver;

    public SecurityContextFilter(PrincipalResolver principalResolver) {
        this.principalResolver = principalResolver;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        try {
            if (request instanceof HttpServletRequest httpRequest) {
                PrincipalContext principal = principalResolver.resolve(httpRequest);
                if (principal != null) {
                    ContextSnapshot existing = ContextAccessor.get();
                    if (existing != null) {
                        ContextSnapshot enriched = new ContextSnapshot(
                                existing.requestId(),
                                existing.correlationId(),
                                existing.startedAtEpochMs(),
                                existing.tenant(),
                                principal,
                                existing.client(),
                                existing.transport(),
                                existing.trace()
                        );
                        ContextAccessor.set(enriched);
                        MDC.put("actorId", principal.actorId());
                        if (existing.tenant() != null) {
                            MDC.put("tenantId", existing.tenant().tenantId());
                        }
                        if (existing.trace() != null && existing.trace().traceId() != null) {
                            MDC.put("traceId", existing.trace().traceId());
                        }
                    }
                    Span current = Span.current();
                    if (current != null && current.isRecording()) {
                        SpanEnricher.enrich(current);
                    }
                }
            }
            chain.doFilter(request, response);
        } finally {
            MDC.remove("actorId");
        }
    }
}
