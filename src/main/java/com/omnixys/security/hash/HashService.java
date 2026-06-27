package com.omnixys.security.hash;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class HashService {

    private final Argon2PasswordEncoder delegate;
    private final String pepper;

    public HashService() {
        this(16, 32, 1, 65536, 3, "");
    }

    public HashService(int saltLength, int hashLength, int parallelism, int memoryKib, int iterations, String pepper) {
        this.delegate = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memoryKib, iterations);
        this.pepper = pepper != null ? pepper : "";
    }

    public String hash(String value) {
        return delegate.encode(value + pepper);
    }

    public boolean verify(String hash, String plain) {
        try {
            return delegate.matches(plain + pepper, hash);
        } catch (Exception e) {
            return false;
        }
    }

    public void dummyVerify() {
        try {
            delegate.matches("dummy", "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$9sZfE6xY7nM");
        } catch (Exception ignored) {
        }
    }
}
