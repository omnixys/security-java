package com.omnixys.security.hash;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    private final SecretKeySpec key;
    private final boolean enabled;

    public EncryptionService(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            this.key = null;
            this.enabled = false;
        } else {
            this.key = new SecretKeySpec(keyBytes, "AES");
            this.enabled = true;
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String encrypt(String plain, boolean urlSafe) {
        if (!enabled) throw new IllegalStateException("EncryptionService is not configured");
        try {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[GCM_IV_LENGTH];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] ciphertext = cipher.doFinal(plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] combined = new byte[GCM_IV_LENGTH + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, GCM_IV_LENGTH);
            System.arraycopy(ciphertext, 0, combined, GCM_IV_LENGTH, ciphertext.length);

            return urlSafe ? Base64.getUrlEncoder().withoutPadding().encodeToString(combined)
                    : Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String payload, boolean urlSafe) {
        if (!enabled) throw new IllegalStateException("EncryptionService is not configured");
        try {
            byte[] combined = urlSafe ? Base64.getUrlDecoder().decode(payload)
                    : Base64.getDecoder().decode(payload);

            if (combined.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted payload");
            }

            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
            byte[] ciphertext = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: invalid payload or key", e);
        }
    }

    public String encrypt(String plain) {
        return encrypt(plain, false);
    }

    public String decrypt(String payload) {
        return decrypt(payload, false);
    }
}
