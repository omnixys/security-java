package com.omnixys.security.session;

import com.omnixys.security.jwe.JweService;
import com.omnixys.security.session.SecureSessionService.SessionIssueOptions;
import com.omnixys.security.session.SecureSessionService.SessionMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecureSessionServiceTest {

    @Mock private JweService jweService;

    private SecureSessionService service;

    @BeforeEach
    void setUp() {
        service = new SecureSessionService(jweService, 3600000L);
    }

    @Test
    void shouldIssueAndReadSession() {
        when(jweService.encrypt(anyString())).thenReturn("encrypted-token");
        when(jweService.decrypt("encrypted-token")).thenReturn(
                "{\"sub\":\"user1\",\"sid\":\"sess-1\",\"iat\":1000000,\"exp\":9999999999999,\"authenticatedAtEpochMs\":1000000}"
        );

        String token = service.issue(Map.of("sub", "user1"), new SessionIssueOptions(
                "sess-1", 3600000L, 1000000L, "strong"
        ));
        assertEquals("encrypted-token", token);

        Map<String, Object> data = service.read(token);
        assertEquals("user1", data.get("sub"));
        assertEquals("sess-1", data.get("sid"));
    }

    @Test
    void shouldReturnMetadata() {
        when(jweService.encrypt(anyString())).thenReturn("encrypted-token");
        when(jweService.decrypt("encrypted-token")).thenReturn(
                "{\"sid\":\"sess-1\",\"iat\":1000000,\"exp\":9999999999999,\"authenticatedAtEpochMs\":2000000,\"authStrength\":\"strong\"}"
        );

        String token = service.issue(Map.of(), new SessionIssueOptions(
                "sess-1", 3600000L, 2000000L, "strong"
        ));

        SessionMetadata meta = service.metadata(token);
        assertEquals("sess-1", meta.sessionId());
        assertEquals(1000000L, meta.issuedAtEpochMs());
        assertEquals(9999999999999L, meta.expiresAtEpochMs());
        assertEquals(2000000L, meta.authenticatedAtEpochMs());
        assertEquals("strong", meta.authStrength());
    }

    @Test
    void shouldThrowWhenSessionExpired() {
        when(jweService.decrypt(anyString())).thenReturn(
                "{\"sid\":\"sess-1\",\"iat\":1000000,\"exp\":1,\"authenticatedAtEpochMs\":1000000}"
        );

        assertThrows(RuntimeException.class, () -> service.read("expired-token"),
                "Session has expired");
    }

    @Test
    void shouldThrowWhenMetadataInvalid() {
        when(jweService.decrypt(anyString())).thenReturn(
                "{\"sid\":null,\"iat\":null,\"exp\":null}"
        );

        assertThrows(RuntimeException.class, () -> service.metadata("bad-token"),
                "Invalid session metadata");
    }
}
