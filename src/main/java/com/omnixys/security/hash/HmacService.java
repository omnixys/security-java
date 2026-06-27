package com.omnixys.security.hash;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HexFormat;

public class HmacService {

    private final byte[] resetTokenKey;
    private final byte[] deviceFingerprintKey;
    private final byte[] magicLinkKey;

    public HmacService(byte[] resetTokenKey, byte[] deviceFingerprintKey, byte[] magicLinkKey) {
        this.resetTokenKey = resetTokenKey;
        this.deviceFingerprintKey = deviceFingerprintKey;
        this.magicLinkKey = magicLinkKey;
    }

    public String hashResetToken(String value) {
        return hmacSha256(resetTokenKey, value);
    }

    public String hashDeviceFingerprint(String value) {
        return hmacSha256(deviceFingerprintKey, value);
    }

    public String hashMagicLink(String value) {
        return hmacSha256(magicLinkKey, value);
    }

    public boolean equals(String aHex, String bHex) {
        byte[] a = HexFormat.of().parseHex(aHex);
        byte[] b = HexFormat.of().parseHex(bHex);
        return MessageDigest.isEqual(a, b);
    }

    public boolean isResetTokenConfigured() {
        return resetTokenKey != null && resetTokenKey.length >= 32;
    }

    public boolean isDeviceFingerprintConfigured() {
        return deviceFingerprintKey != null && deviceFingerprintKey.length >= 32;
    }

    public boolean isMagicLinkConfigured() {
        return magicLinkKey != null && magicLinkKey.length >= 32;
    }

    private String hmacSha256(byte[] key, String value) {
        if (key == null || key.length < 32) {
            throw new IllegalStateException("HMAC key is not configured");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] digest = mac.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("HMAC computation failed", e);
        }
    }
}
