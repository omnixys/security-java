package com.omnixys.security.revocation;

public class TokenRevocationService {

    private final RevocationStore store;

    public TokenRevocationService(RevocationStore store) {
        this.store = store;
    }

    public void revoke(String jti, long ttlSec) {
        store.set("revoked:" + jti, "1", ttlSec);
    }

    public boolean isRevoked(String jti) {
        return store.exists("revoked:" + jti);
    }

    public interface RevocationStore {
        void set(String key, String value, long ttlSec);
        boolean exists(String key);
    }
}
